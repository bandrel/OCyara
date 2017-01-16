#!/usr/bin/env python3
import glob
import io
import os
import tesserocr
import yara
from multiprocessing import Process, JoinableQueue, Lock, Manager, cpu_count
from queue import Empty
import tempfile
from PIL import Image
import argparse


class OCyara:
    """
    Performs OCR (Optical Character Recognition) on image files and scans for matches to Yara rules.

    OCyara also can process images embedded in PDF files.
    """
    def __init__(self, path, recursive=False, worker_count=cpu_count() * 2):
        """
        Create an OCyara object that can scan the specified directory or file and store the results.

        Arguments:
            path -- File or directory to be processed

        Keyword Arguments:
            recursive -- Whether the specified path should be recursivly searched for images (default False)
            worker_count -- The number of worker processes that should be spawned when
              run() is executed (default availble CPUcores * 2)
        """
        self.path = path
        self.recursive = recursive
        self.q = JoinableQueue()
        self.results = {}
        self.threads = worker_count
        self.lock = Lock()
        self.workers = []
        if os.path.isdir(self.path):
            if self.path[-1] is '/':
                self.path += '*'
            else:
                self.path += '/*'
        self.manager = Manager()
        self.matchedfiles = self.manager.list()
        self.matchedfiles.append({})
        self.total_items_to_queue = self.manager.list([0])
        self.total_added_to_queue = self.manager.list([0])
        self.tempdir = tempfile.TemporaryDirectory()

    # def __call__(self):
    #     for rule in self.list_rules():
    #         self.list_matches(rule)

    def run(self, yara_rule, auto_join=True):
        """
        Begin multithreaded processing of path files with the specified rule file.

        Arguments:
            yara_rule -- A string file path of a Yara rule file

        Keyword Arguments:
            auto_join -- If set to True, the main process will stall until all the
              worker processes have completed their work. If set to False, join()
              must be manually called following run() to ensure the queue is
              cleared and all workers have terminated.
        """

        # Populate the queue with work
        if type(self.path) == str:
            # r1 = yara.compile(source='rule pdf { '
            #                          '  condition: magic.type() contains “PDF”'
            #                          '} rule jpg { '
            #                          '  condition: magic.type() contains “JPG”}')
            all_files = glob.glob(self.path, recursive=self.recursive)
            # items_to_queue = r1.matches(data=all_files)
            # Determine the number of items that will be queued so workers can exit only after queuing is completed
            items_to_queue = [i for i in all_files if i.split('.')[-1] in ['png', 'jpg', 'pdf']]
            self.total_items_to_queue[0] = len(items_to_queue)
            # Create and run the workers
            for i in range(self.threads):
                p = Process(target=self._process_image, args=(yara_rule,))
                # p = Process(target=print, args=[yara_rule])
                self.workers.append(p)
                p.start()
            # add items to queue for processing
            for filepath in items_to_queue:
                # Strip jpegs from PDF files and add them to the queue
                if filepath.split('.')[-1].upper() == 'PDF':
                    self._pdf_extract(filepath)
                    for jpg_file in glob.glob(self.tempdir.name+'/*.jpg'):
                        self.total_items_to_queue[0] += 1
                        self.q.put([Image.open(jpg_file), filepath])
                        self.total_added_to_queue[0] += 1
                    self.total_items_to_queue[0] -= 1  # Negate PNG file itself (vs jpegs) being added earlier
                else:
                    self.q.put([Image.open(filepath), filepath])
                    self.total_added_to_queue[0] += 1
        elif type(self.path) == io.BufferedReader:
            self.q.put(Image.open(self.path))
            self.total_added_to_queue[0] += 1
        if auto_join:
            self.join()

    def join(self):
        """Join the main thread to the scan queue and wait for workers to complete before proceding."""
        self.q.join()
        for worker in self.workers:
            worker.join()

    def list_matches(self, rulename):
        """Find scanned files that matched the specified rule and return them in a dictionary."""
        files = []
        for filepath, matchedrule in self.matchedfiles[0].items():
            if rulename in matchedrule:
                files.append(filepath)
        return dict(rule=files)

    def list_rules(self):
        """Process the matchedfiles dictionary and return a list of rules that were matched."""
        rules = set()
        for filepath, matchedrules in self.matchedfiles[0].items():
            [rules.add(matchedrule) for matchedrule in matchedrules]
        return rules

    def _process_image(self, yara_rule):
        """
        Perform OCR and yara rule matching as a worker.

        process_image() is used by the run() method to create multiple worker processes for
        parallel execution.  process_image normally will not be called directly.

        Arguments:
            yara_rule -- File path pointing to a Yara rule file
        """
        while True:
            try:
                image, filepath = self.q.get(timeout=.25)
            except Empty:
                if self.total_added_to_queue[0] == self.total_items_to_queue[0]:
                    return
                else:
                    continue
            ocrtext = tesserocr.image_to_text(image)
            rules = yara.compile(yara_rule)
            matches = rules.match(data=ocrtext)
            # if there is a match store the filename and the rule in a dictionary local to this process
            # Create an editable copy of the master manager dict
            with self.lock:
                local_results_dict = self.matchedfiles[0]
                if matches:
                    for x in matches:
                        try:
                            local_results_dict[filepath].append(x.rule)
                        except KeyError:
                            local_results_dict[filepath] = [x.rule]
                    self.matchedfiles[0] = local_results_dict
            self.q.task_done()

    def _pdf_extract(self, pdffile):
        """
        Extract jpg images from pdf files and save them to temp directory.

        pdf_extract is used by the run() method and not be called directly in most
        circumstances.

        Arguments:
            pdffile -- A string file path pointing to a PDF
        """
        with open(pdffile, "rb") as file:
            pdf = file.read()

        startmark = b"\xff\xd8"
        startfix = 0
        endmark = b"\xff\xd9"
        endfix = 2
        i = 0
        pdf_images = []
        njpg = 0
        while True:
            istream = pdf.find(b"stream", i)
            if istream < 0:
                break
            istart = pdf.find(startmark, istream, istream + 20)
            if istart < 0:
                i = istream + 20
                continue
            iend = pdf.find(b"endstream", istart)
            if iend < 0:
                raise Exception("Didn't find end of stream!")
            iend = pdf.find(endmark, iend - 20)
            if iend < 0:
                raise Exception("Didn't find end of JPG!")

            istart += startfix
            iend += endfix
            jpg = pdf[istart:iend]
            with open(self.tempdir.name + "/jpg%d.jpg" % njpg, "wb") as jpgfile:
                jpgfile.write(jpg)
            njpg += 1
            i = iend


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OCyara performs OCR (Optical Character Recognition) on image '
                                                 'files and scans them for matches to Yara rules '
                                                 '(https://virustotal.github.io/yara/). OCyara also can process images '
                                                 'embedded in PDF files.')
    parser.add_argument('YARA_RULES_FILE', type=str, help='Path of file containing yara rules')
    parser.add_argument('TARGET_FILE/S', type=str, help='Directory or file name of images to scan.')
    args = parser.parse_args()
    ocy = OCyara(args.FILE)
    ocy.run(args.RULES_FILE)
    for rule in ocy.list_rules():
        for k,v in ocy.list_matches(rule).items():
            for i in v:
                print(rule, i)
