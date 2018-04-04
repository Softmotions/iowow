import subprocess
from bokeh.plotting import figure, output_file, show
from bokeh.models import ColumnDataSource, FactorRange
from bokeh.transform import factor_cmap
from parse import parse

basedir = '/home/adam/Projects/softmotions/iowow/build/src/kv/benchmark'
random_seed = 1747454607

benchmarks = [
    'iwkv_benchmark',
    'lmdb_benchmark'
    # 'leveldb_benchmark',
    # 'kyc_benchmark'
]

runs = []

runs += [{'b': 'fillseq2,readrandom,readseq,deleteseq', 'n': n, 'vz': vz, 'rs': random_seed}
         for n in (int(1e2), int(1e3))
         for vz in (100, 600)]

# runs += [{'b': 'fillseq,overwrite,readrandom,deleterandom', 'n': n, 'vz': vz}
#          for n in (5e5, 1e6)
#          for vz in (100, 600)]

# runs += [{'b': 'fillrandom2,readrandom', 'n': n, 'vz': vz}
#          for n in (5e3, 10e3)
#          for vz in (100 * 1024, 200 * 1024)]

metrics = {
    'exec size': 'exec size: {}',
    'db size': 'db size: {} ({})',
}

tests = [
    'fillseq',
    'fillseq2',
    'fillrandom',
    'fillrandom2',
    'overwrite',
    'fillsync',
    'fill100K',
    'deleteseq',
    'deleterandom',
    'readseq',
    'readreverse',
    'readrandom',
    'readmissing',
    'readhot',
    'seekrandom'
]

results = {}


def fill_result(bm, run, line):
    key = ' '.join(['-{} {}'.format(a, v) for a, v in run.items()])
    if key not in results:
        results[key] = {}
    if bm not in results[key]:
        results[key][bm] = {}
    res = results[key][bm]

    pval = parse('done: {} in {}', line)
    if pval:
        print(line, flush=True)
        res[pval[0]] = int(pval[1])
    else:
        for m, p in metrics.items():
            pval = parse(p, line)
            if pval and m not in res:
                res[m] = pval[0]


def run_benchmark_run(bm, run):
    args = ['{}/{}'.format(basedir, bm)]
    for a, v in run.items():
        args.append('-{}'.format(a))
        args.append(str(v))
    print('Run {}'.format(' '.join(args)), flush=True)
    with subprocess.Popen(args,
                          stderr=subprocess.STDOUT,
                          stdout=subprocess.PIPE,
                          universal_newlines=True,
                          cwd=basedir,
                          bufsize=1) as output:
        for line in output.stdout:
            fill_result(bm, run, line.strip())
        output.wait()


def run_benchmark(bm):
    for run in runs:
        run_benchmark_run(bm, run)


def run():
    for b in benchmarks:
        run_benchmark(b)


def main():
    run()
    print(results)
# {
#   'lmdb_benchmark': {
#     'engine': 'LMDB 0.9.70',
#     'exec size': '494872',
#     'db size': '417792',
#     'readseq': 0,
#     'read records': '1000',
#     'fillseq2': 13,
#     'seed': '3461453708',
#     'num records': '1000',
#     'deleteseq': 11,
#     'readrandom': 1,
#     'value size': '600'
#   },
#   'iwkv_benchmark': {
#     'engine': 'IWKV 1.0.0',
#     'exec size': '180744',
#     'db size': '8192',
#     'readseq': 8,
#     'read records': '1000',
#     'fillseq2': 10,
#     'seed': '3847133068',
#     'num records': '1000',
#     'deleteseq': 11,
#     'readrandom': 11,
#     'value size': '600'
#   }
# }


output_file('runbench.html')

# p = figure()
# p.line([1, 2, 3, 4, 5], [6, 7, 2, 4, 5], line_width=2)
# print(runs)
# show(p)


if __name__ == '__main__':
    main()
