#!/usr/bin/python

import sys

from . utils import dbg
from . utils import dbg, print_elapsed_time, restart_counting_time
from . utils.process import runcmd, ProcessRunner
from . utils.watch import ProcessWatch, DbgWatch
from . utils.utils import print_stderr, print_stdout
from . exceptions import SymbioticException, SymbioticExceptionalResult

def initialize_verifier(opts):
    from . targets import targets
    try:
        return targets[opts.tool_name](opts)
    except KeyError:
        raise SymbioticException('Unknown verifier: {0}'.format(opts.tool_name))

class ToolWatch(ProcessWatch):
    def __init__(self, tool):
        # store the whole output of a tool
        ProcessWatch.__init__(self, None)
        self._tool = tool

    def parse(self, line):
        if b'ERROR' in line or b'WARN' in line or b'Assertion' in line\
           or b'error' in line or b'warn' in line:
            # XXX: this seems horrible, but the line may contain non-ascii characters
            sys.stderr.write(str(line.strip()))
            sys.stderr.write('\n')
        else:
            dbg(str(line), 'all', print_nl=False,
                prefix='', color=None)

class SymbioticVerifier(object):
    """
    Instance of symbiotic tool. Instruments, prepares, compiles and runs
    symbolic execution on given source(s)
    """

    def __init__(self, bitcode, sources, tool, opts, env=None, params=None):
        # original sources (needed for witness generation)
        self.sources = sources
        # source compiled to llvm bitecode
        self.curfile = bitcode
        # environment
        self.env = env
        self.options = opts

        self.override_params = params

        # definitions of our functions that we linked
        self._linked_functions = []

        # tool to use
        self._tool = tool

    def command(self, cmd):
        return runcmd(cmd, DbgWatch('all'),
                      "Failed running command: {0}".format(" ".join(cmd)))

    def _run_tool(self, tool, prp, params, timeout):
        cmd = []
        if timeout:
            cmd = ['timeout', str(int(timeout))]
        cmd += tool.cmdline(tool.executable(), params,
                            [self.curfile], prp, [])
        watch = ToolWatch(tool)
        process = ProcessRunner()

        returncode = process.run(cmd, watch)
        if returncode != 0:
            dbg('The verifier return non-0 return status')

        res = tool.determine_result(returncode, 0,
                                    map(str, watch.getLines()),
                                    False)
        if res.lower().startswith('error'):
            for line in watch.getLines():
                print_stderr(line.decode('utf-8'),
                             color='RED', print_nl=False)
        return res

    def _run_verifier(self, tool, addparams, timeout):
        params = self.override_params or self.options.tool_params
        if addparams:
            params = params + addparams
        prp = self.options.property.getPrpFile()
        return self._run_tool(tool, prp, params, timeout)

    def run_verification(self):
        print_stdout('INFO: Starting verification', color='WHITE')
        restart_counting_time()
        for verifiertool, addparams, verifiertimeout in self._tool.verifiers():
            res = self._run_verifier(verifiertool, addparams, verifiertimeout)
            sw = res.lower().startswith
            # we got an answer, we can finish
            if sw('true') or sw('false'):
                return res, verifiertool
            print(f"{verifiertool.name()} answered {res}")
        print_elapsed_time("INFO: Verification time", color='WHITE')
        return res, None

    def run(self):
        try:
            return self.run_verification()
        except KeyboardInterrupt as e:
            raise SymbioticException('interrupted')
        except SymbioticExceptionalResult as res:
            # we got result from some exceptional case
            return str(res), None

