#!/usr/bin/env python3
import glob
import io
import os
import tesserocr
import yara
from multiprocessing import Process, JoinableQueue, Lock, Manager, cpu_count
from queue import Empty

from PIL import Image
import argparse


def pdf_extract(pdffile):
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
        with open("jpg%d.jpg" % njpg, "wb") as jpgfile:
            jpgfile.write(jpg)
        # jpgfile = tempfile.TemporaryFile(mode='w+b')
        # pdf_images.append(jpgfile.name)
        pdf_images.append("jpg%d.jpg" % njpg)
        njpg += 1
        i = iend
    return pdf_images


class OCyara:
    """
    Whole Class doc string
    """

    def __init__(self, path, recursive=False, threads=cpu_count() * 2):
        self.path = path
        self.recursive = recursive
        self.q = JoinableQueue()
        self.results = {}
        self.threads = threads
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

    def __repr__(self):
        for rule in self.list_rules():
            self.list_matches(rule)

    def run(self, yara_rule, auto_join=True):
        """ Begin multithreaded processing of path files.
        If auto_join is set to True the main process will stall until all of the worker processes have completed
        their work. If auto_join is set to False the main process must use the .join() method before exiting the main
         proccess because it will be possible for the main process to finish before the worker processes do."""

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
                p = Process(target=self.process_image, args=(yara_rule,))
                # p = Process(target=print, args=[yara_rule])
                self.workers.append(p)
                p.start()
            # add items to queue for processing
            for filepath in items_to_queue:
                # Strip jpegs from PDF files and add them to the queue
                if filepath.split('.')[-1].upper() == 'PDF':
                    jpg_files = pdf_extract(filepath)
                    for jpg_file in jpg_files:
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
        self.q.join()
        for p in self.workers:
            p.join()

    def list_matches(self, rule):
        files = []
        for k, v in self.matchedfiles[0].items():
            if rule in v:
                files.append(k)
        return dict(rule=files)

    def list_rules(self):
        rules = set()
        for k, v in self.matchedfiles[0].items():
            [rules.add(i) for i in v]
        return rules

    def process_image(self, yara_rule):
        """ Worker function """
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Use OCR to scan jpg, png or images imbedded in PDF documents')
    parser.add_argument('RULES_FILE', type=str, help='path of file containing yara rules')
    parser.add_argument('FILE', type=str, help='path or file name of images to scan.')
    args = parser.parse_args()
    ocy = OCyara(args.FILE)
    ocy.run(args.RULES_FILE)
    for rule in ocy.list_rules():
        for k,v in ocy.list_matches(rule).items():
            print(k,[i for i in v])

