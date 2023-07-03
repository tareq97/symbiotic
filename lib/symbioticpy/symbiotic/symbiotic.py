#!/usr/bin/env python3

import os
import sys
import re
import glob

from . transform import SymbioticCC,PrintWatch
from . verifier import SymbioticVerifier
from . options import SymbioticOptions
from . utils import err, dbg, print_elapsed_time, restart_counting_time
from . utils.utils import print_stdout
from . utils.process import ProcessRunner,runcmd
from . exceptions import SymbioticExceptionalResult,SymbioticException
import shutil
from pathlib import Path

import csv

class Symbiotic(object):
    """
    Instance of symbiotic tool. Instruments, prepares, compiles and runs
    symbolic execution on given source(s)
    """

    def __init__(self, tool, src, opts=None, env=None):
        # source file
        self.sources = src
        # source compiled to llvm bytecode
        self.curfile = None
        # environment
        self.env = env

        if opts is None:
            self.options = SymbioticOptions()
        else:
            self.options = opts

        # tool to use
        self._tool = tool

    def terminate(self):
        pr = ProcessRunner()
        if pr.hasProcess():
            pr.terminate()

    def kill(self):
        pr = ProcessRunner()
        if pr.hasProcess():
            pr.kill()

    def kill_wait(self):
        pr = ProcessRunner()
        if not pr.hasProcess():
            return

        if pr.exitStatus() is None:
            from time import sleep
            while pr.exitStatus() is None:
                pr.kill()

                print('Waiting for the child process to terminate')
                sleep(0.5)

            print('Killed the child process')

    #def line_no(self,strs):
    #    lineNoArr = []
    #    print(strs)
    #    if strs.__contains__("Line:"):
    #        lineNoArr = strs.split(":")
    #    return lineNoArr[1].strip()
    
    #def info(strs):
    #    if strs.__contains__("address:"):
    #        addressArr = strs.split(":")
    #        address = addressArr[1].split(":")
    #    return address[1].strip()
    
    #def pointing_to(strs):
    #    if strs.__contains__("pointing"):
    #        sizeArr = strs.split(":")
    #        sizeArr = sizeArr[-1].strip()
    #    return sizeArr            


    #def get_cv_from_klee(self,cv):
    #    print_stdout("This is the ulimate method that %s", cv)
        
    #    klee_test_0_path = cv.split("=")
    #    print_stdout("This is the ulimate method that %s", str(klee_test_0_path))
    #    klee_test_0_path_name = klee_test_0_path[1]
    #    klee_test_0_path_name = klee_test_0_path_name[:-1]
    #    klee_testcase_filename = os.path.basename(klee_test_0_path_name)
    #    klee_testcase_filename_list = klee_testcase_filename.split('.')
    #    klee_test_case_mention = klee_testcase_filename_list[0]
    #    klee_dir_name = os.path.dirname(klee_test_0_path_name)

    #    f = open(klee_dir_name + "/" + klee_test_case_mention + ".ptr.err", "r")
        #print("Is this printed anywhere ::: %s", str(f.read())) 

    #    lines = f.readlines()
        # extract address and size information
        
        # extract line no
        # extract information cv

    #    for line in lines:
    #        self.line_no(line)
    #        self.info(line) 
    #        self.pointing_to(line)  

    #        if line.__contains__("Crash Variables:"):
    #            while(line != ''):
    #                print(line)
        
    def getSlicingInfo(self,paths):
        slicing_criteria = ""
        print_stdout("INFO ::Start from crash text file.",color='RED')
        print_stdout(str(paths), color='RED')
        paths = str(paths) + "/" + "crash.txt"
        if os.path.isfile(paths):
            print_stdout("INFO :: This is info from crash text file.",color='RED')
            f = open(str(paths), "r")
            s = f.readline()
            s = s.split(",")
            s = [x for x in s if x != '']
            print_stdout("NIFO :: This is info from crash text file. %s", str(s),color='RED')
            for q in s[1:-1]:
                print("First")
                print(q)
                if q == s[-2]:
                    slicing_criteria = slicing_criteria + s[0] + ":" + q
                    print(slicing_criteria)    
                    print(len(s))
                else:
                    slicing_criteria = slicing_criteria + s[0] + ":" + q + ","
                    print(slicing_criteria)
            print_stdout("This is slicing criteria :: %s", str(slicing_criteria),color='RED')

            f.close()

        print_stdout(slicing_criteria, color='RED')
        return slicing_criteria
    
    def generateCFC(self,str):
        #read crash.txt and malloc_info and create a cfc.txt file
        f = open(str+'/crash.txt')
        csv_f = csv.reader(f)
        for row in csv_f:
            print("**********************CRASH INFO************************")
            print(row)
            print("**********************END CRASH INFO************************")
        f1 = open(str+'/malloc_info.txt')
        csv_f1 = csv.reader(f1)
        for row in csv_f1:
            print("**********************CRASH INFO************************")
            print(row)
            print("**********************END CRASH INFO************************")
        
        f = open(str+'/cfc.txt')



    def replay_nonsliced(self, tool, cc):
        bitcode = cc.prepare_unsliced_file()
        
        params = []
        if hasattr(tool, "replay_error_params"):
            params = tool.replay_error_params(cc.curfile)
            klee_file_name = params[0].split("=")
            slicer_params = self.getSlicingInfo(os.path.dirname(os.path.dirname(klee_file_name[1])))
            self.generateCFC(os.path.dirname(os.path.dirname(klee_file_name[1])))
            ## add slicer again here and change the sliced file name to final_slice.bc
            #SymbioticCC.slicer(self,add_params=['-c',slicer_params])
            print_stdout("Tis is cur file :::::: %s", str(cc.curfile),color='RED')
            cmd = ['timeout', '300', 'sbt-slicer','-c', slicer_params,cc.curfile] 

            try:
                runcmd(cmd, PrintWatch('INFO: ' + str(cmd)), 'Ran slicer againer for final time')
                print_stdout("***************START******************",color='RED')
                print_stdout(str(cmd),color='RED')
                print_stdout("***************END******************",color='RED')
                list_of_files = glob.glob(os.path.dirname(cc.curfile) + "/" + '*.sliced') # * means all if need specific format then *.csv
                latest_file = max(list_of_files, key=os.path.getctime)
                
                shutil.copyfile(latest_file, str(os.path.dirname(cc.curfile) + "/" + Path(latest_file).stem) + ".bc")
                file_name_use = str(os.path.dirname(cc.curfile) + "/" + Path(latest_file).stem) + ".bc"


            except SymbioticException:
            # not fatal, continue working
                dbg('Failed running slicer in replay')

        print_stdout('INFO: Replaying error path', color='WHITE')
        restart_counting_time()

        #verifier = SymbioticVerifier(bitcode, self.sources,
        #                             tool, self.options,
        #                             self.env, params)
        verifier = SymbioticVerifier(file_name_use,self.sources, 
                                    tool, self.options, 
                                    self.env, params)
        res, _ = verifier.run()

        print_elapsed_time('INFO: Replaying error path time', color='WHITE')

        return res

    def _run_symbiotic(self):
        options = self.options
        cc = SymbioticCC(self.sources, self._tool, options, self.env)
        bitcode = cc.run()

        if options.no_verification:
            return 'No verification'

        verifier = SymbioticVerifier(bitcode, self.sources,
                                     self._tool, options, self.env)
        # result and the tool that decided this result
        res, tool = verifier.run()

        # if we crashed on the sliced file, try running on the unsliced file
        # (do this optional, as well as for slicer and instrumentation)
        resstartswith = res.lower().startswith
        if (not options.noslice) and \
           (options.sv_comp or options.test_comp) and \
           (resstartswith('error') or resstartswith('unknown')):
            print_stdout("INFO: Failed on the sliced code, trying on the unsliced code",
                         color="WHITE")
            options.replay_error = False # now we do not need to replay the error
            options.noslice = True # now we behave like without slicing
            bitcode = cc.prepare_unsliced_file()
            verifier = SymbioticVerifier(bitcode, self.sources,
                                         self._tool, options, self.env)
            res, tool = verifier.run()
            print_elapsed_time('INFO: Running on unsliced code time', color='WHITE')

        if tool and options.replay_error and not tool.can_replay():
           dbg('Replay required but the tool does not support it')

        has_error = res and\
                    (res.startswith('false') or\
                    (res.startswith('done') and options.property.errorcall()))
        if has_error and options.replay_error and\
           not options.noslice and tool.can_replay():
            print_stdout("Trying to confirm the error path")
            newres = self.replay_nonsliced(tool, cc)

            dbg("Original result: '{0}'".format(res))
            dbg("Replayed result: '{0}'".format(newres))

            if res != newres:
                # if we did not replay the original error, but we found a different error
                # on this path, report it, since it should be real
                has_error = newres and\
                            (newres.startswith('false') or\
                            (newres.startswith('done') and\
                             options.property.errorcall()))
                if has_error:
                    res = newres
                else:
                    res = 'cex not-confirmed'
                    has_error = False

        if res == 'cex not-confirmed':
            # if we failed confirming CEX, rerun on unsliced file
            bitcode = cc.prepare_unsliced_file()
            verifier = SymbioticVerifier(bitcode, self.sources,
                                         self._tool, options, self.env)
            res, tool = verifier.run()
            has_error = res and\
                        (res.startswith('false') or\
                        (res.startswith('done') and options.property.errorcall()))
 
        if has_error and hasattr(tool, "describe_error"):
            tool.describe_error(cc.curfile)

        if has_error and options.executable_witness and\
           hasattr(tool, "generate_exec_witness"):
            tool.generate_exec_witness(cc.curfile, self.sources)

        if not options.nowitness and hasattr(tool, "generate_witness"):
            tool.generate_witness(cc.curfile, self.sources, has_error)

        return res

    def run(self):
        try:
            return self._run_symbiotic()
        except KeyboardInterrupt:
            self.terminate()
            self.kill()
            print('Interrupted...')
            return 'interrupted'
        except SymbioticExceptionalResult as res:
            # we got result from some exceptional case
            return str(res)

