#!/usr/bin/env python3
import argparse
import glob
import io
import os
import tempfile
import tesserocr
import yara
from multiprocessing import Process, JoinableQueue, Lock, Manager, cpu_count
from queue import Empty
from time import sleep

import colorlog
from PIL import Image
from tqdm import tqdm
import subprocess
from typing import Dict, Set, Tuple, Union


class OCyara:
    """
    Performs OCR (Optical Character Recognition) on image files and scans for matches to Yara rules.

    OCyara also can process images embedded in PDF files.
    """

    def __init__(self, path: str, recursive=False, worker_count=cpu_count() * 2, verbose=0) -> None:
        """
        Create an OCyara object that can scan the specified directory or file and store the results.

        Arguments:
            path -- File or directory to be processed

        Keyword Arguments:
            recursive -- Whether the specified path should be recursivly searched for images (default False)
            worker_count -- The number of worker processes that should be spawned when
                            run() is executed (default available CPU cores * 2)
            verbose -- An int() from 0-2 that sets the verbosity level.
                       0 is default, 1 is information and 2 is debug
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
        self.matchedfiles = None
        self.total_items_to_queue = None
        self.total_added_to_queue = None
        self.queue_items_completed = None
        self.tempdir = tempfile.TemporaryDirectory()
        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter(
                '%(log_color)s%(levelname)s:%(name)s:%(message)s'))
        self.logger = colorlog.getLogger('OCyara')
        self.logger.addHandler(handler)
        if verbose == 1:
            self.logger.setLevel('INFO')
        elif verbose > 1:
            self.logger.setLevel('DEBUG')
        else:
            self.logger.setLevel('WARN')

    def run(self, yara_rule: str, auto_join=True, show_progress=True, file_magic=False, save_context=False) -> None:
        """
        Begin multithreaded processing of path files with the specified rule file.

        Arguments:
            yara_rule -- A string file path of a Yara rule file

        Keyword Arguments:
            auto_join -- If set to True, the main process will stall until all the
              worker processes have completed their work. If set to False, join()
              must be manually called following run() to ensure the queue is
              cleared and all workers have terminated.

            show_progress -- Display a progress bar when join() is used.

            file_magic -- If file_magic is enabled, ocyara will examine the contents
              of the target files to determine if they are an eligible image file
              type. For example, a JPEG file named 'picture.txt' will be processed by
              the OCR engine. file_magic uses the Linux "file" command.

            save_context -- If True, when a file matches a yara rule, the returned
              results dictionary will also include the full ocr text of the matched
              file. This text can be further processed by the user if needed.
        """

        # Populate the queue with work
        if type(self.path) == str:
            self.logger.debug('Input file detected as a path')
            if self.recursive:
                self.path = self.path.rstrip('/') + '/**'
            all_files = glob.glob(self.path, recursive=self.recursive)
            handled_file_extensions = ['png', 'jpg', 'jpeg', 'pdf', 'gif', 'bmp']
            handled_mime_types = [
                'image/png', 'image/jpeg', 'application/pdf', 'image/gif', 'image/x-ms-bmp'
            ]
            # Intialize counters to 0 and create an empty matchedfiles dict
            self.total_items_to_queue = self.manager.list([0])
            self.total_added_to_queue = self.manager.list([0])
            self.queue_items_completed = self.manager.list([0])
            self.matchedfiles = self.manager.list()
            self.matchedfiles.append({})

            # Determine the number of items that will be queued so workers can exit only after queuing is completed
            if file_magic:
                # Queue files base on file contents
                items_to_queue = [
                    filepath for filepath in all_files if self.check_file_type(filepath) in handled_mime_types
                ]
            else:
                # Queue files based on extension
                items_to_queue = [
                    filepath for filepath in all_files if filepath.split('.')[-1] in handled_file_extensions
                ]
            self.total_items_to_queue[0] = len(items_to_queue)
            self.logger.info('{0} items detected and will be added to the Queue'.format(self.total_items_to_queue[0]))
            # Create and run the workers
            self.logger.info('{0} worker processes being generated to process images. from the '
                             'queue'.format(self.threads))
            for i in range(self.threads):
                p = Process(target=self._process_image, args=(yara_rule, save_context))
                self.workers.append(p)
                p.start()
            # Add items to queue for processing
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
                    try:
                        self.q.put([Image.open(filepath), filepath])
                        self.total_added_to_queue[0] += 1
                    except OSError:
                        self.logger.warning('Warning: {0} is not a proper image file'.format(filepath))
                        self.total_items_to_queue[0] -= 1
        elif type(self.path) == io.BufferedReader:
            self.q.put(Image.open(self.path))
            self.total_added_to_queue[0] += 1
        if auto_join:
            self.join(show_progress)

    def show_progress(self) -> None:
        """Generate a progress bar based on the number of items remaining in queue."""
        previous_queue_items_completed = 0
        with tqdm(total=self.total_added_to_queue[0], desc='Processing Images', unit='Image') as progressbar:
            while True:
                difference = self.queue_items_completed[0] - previous_queue_items_completed
                previous_queue_items_completed = self.queue_items_completed[0]
                progressbar.update(difference)
                if self.queue_items_completed[0] == self.total_added_to_queue[0]:
                    break
                sleep(.25)

    def join(self, showprogress=True):
        if showprogress:
            self.show_progress()
        self.q.join()
        for worker in self.workers:
            worker.join()

    def list_matches(self, rules_matched=None) -> Dict[str, Set[Tuple[str, Union[str, None]]]]:
        """
        List matched files and thier contexts (if available) in dictionary form.

        Keyword Arguments:

            rules -- Accepts a string or list of strings indicating specific rules.
              Only matches pertaining to the specified rule/s will be returned. If no
              rules are specified, all matches will be returned.
        """
        matches_to_return = {}
        if type(rules_matched) is str:
            rules_matched = [rules_matched]
        if rules_matched is None:
            rules_matched = self.list_matched_rules()
        # Step through each matched file and see if they matched any of the rules we're interested in.
        for filepath, matchedrules_with_contexts in self.matchedfiles[0].items():
            for matchedrulename, context in matchedrules_with_contexts:
                for rulename in rules_matched:
                    if matchedrulename == rulename:
                        try:
                            matches_to_return[rulename].add((filepath, context))
                        except KeyError:
                            matches_to_return[rulename] = {(filepath, context)}
        return matches_to_return

    def list_matched_rules(self) -> set:
        """Process the matchedfiles dictionary and return a list of rules that were matched."""
        rules = set()
        for filepath, matchedrules in self.matchedfiles[0].items():
            [rules.add(matchedrule[0]) for matchedrule in matchedrules]
        return rules

    def _process_image(self, yara_rule: str, save_context: bool) -> None:
        """
        Perform OCR and yara rule matching as a worker.

        process_image() is used by the run() method to create multiple worker processes for
        parallel execution.  process_image normally will not be called directly.

        Arguments:
            yara_rule -- File path pointing to a Yara rule file
        """
        context = None
        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter(
                '%(log_color)s%(levelname)s:%(name)s:%(message)s'))
        # Creates a logger object for the individual workers that contains the PID as part of the message header
        worker_logger = colorlog.getLogger('worker_'+str(os.getpid()))
        worker_logger.addHandler(handler)
        worker_logger.setLevel(self.logger.level)
        worker_logger.info('PID {0} created to process queue'.format(str(os.getpid())))
        while True:
            try:
                image, filepath = self.q.get(timeout=.25)
            except Empty:
                if self.total_added_to_queue[0] == self.total_items_to_queue[0]:
                    worker_logger.debug('Queue Empty PID %d exiting' % os.getpid())
                    return
                else:
                    worker_logger.debug('Queue still loading')
                    continue
            ocrtext = tesserocr.image_to_text(image)
            try:
                rules = yara.compile(yara_rule)
            except yara.Error:
                worker_logger.error('Invalid rule file/rule file not found: {0}'.format(yara_rule))
            matches = rules.match(data=ocrtext)
            # If there is a match, store the filename and the rule in a dictionary local to this process.
            # Create an editable copy of the master manager dict.
            with self.lock:
                local_results_dict = self.matchedfiles[0]
                if matches:
                    if save_context:
                        context = ocrtext
                    for x in matches:
                        try:
                            local_results_dict[filepath].append((x.rule, context))
                        except KeyError:
                            local_results_dict[filepath] = [(x.rule, context)]
                    self.matchedfiles[0] = local_results_dict
            self.queue_items_completed[0] += 1
            self.q.task_done()

    def _pdf_extract(self, pdffile: str) -> None:
        """
        Extract jpg images from pdf files and save them to temp directory.

        pdf_extract is used by the run() method and not be called directly in most
        circumstances.

        Arguments:
            pdffile -- A string file path pointing to a PDF
        """
        self.logger.info('Opening %s and extracting JPG images' % pdffile)
        with open(pdffile, "rb") as file:
            pdf = file.read()

        startmark = b"\xff\xd8"
        startfix = 0
        endmark = b"\xff\xd9"
        endfix = 2
        i = 0
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
            self.logger.debug('Creating temporary file ' + self.tempdir.name + "/jpg%d.jpg" % njpg)
            with open(self.tempdir.name + "/jpg%d.jpg" % njpg, "wb") as jpgfile:
                jpgfile.write(jpg)
            njpg += 1
            i = iend

    @staticmethod
    def check_file_type(path: str) -> str:
        """
        Use the Linux "file" command to determine a file's type based on contents
        instead of file extension.

        Arguments:
            path -- A string file path to be processed
        """
        process = subprocess.run(['file', '--mime-type', '-b', path], stdout=subprocess.PIPE)
        filemimetype = process.stdout.decode("utf-8").strip()
        return filemimetype

    def __call__(self):
        """Default call which outputs the results with the same output standard as the regular yara program """
        print(ocy.yara_output)

    @property
    def yara_output(self) -> str:
        """
        Returns the same output format as the standard yara program:
        RuleName FileName, FileName
        RuleName FileName...

        Where:
          RuleName is the name of the rule that was matched
          FileName is the name of the file in which the match was found
        """
        output_text = ''
        for rule, matched_files_and_contexts in self.list_matches().items():
            for matched_file_and_context in matched_files_and_contexts:
                output_text += rule + ' ' + matched_file_and_context[0] + '\n'
        return output_text


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OCyara performs OCR (Optical Character Recognition) on image '
                                                 'files and scans them for matches to Yara rules '
                                                 '(https://virustotal.github.io/yara/). OCyara also can process images '
                                                 'embedded in PDF files.')
    parser.add_argument('YARA_RULES_FILE', type=str, help='Path of file containing yara rules')
    parser.add_argument('TARGET_FILES', type=str, help='Directory or file name of images to scan.')
    parser.add_argument('-v', action='count', help='Enables verbose output, -v for verbose or -vv for very verbose',
                        default=0)
    args = parser.parse_args()
    ocy = OCyara(args.TARGET_FILES, verbose=args.v)
    ocy.run(args.YARA_RULES_FILE)
    ocy()
