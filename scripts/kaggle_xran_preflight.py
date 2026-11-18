"""Inspect the actual Kaggle accelerator and estimate endpoint training cost."""

import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import time

started = time.monotonic()
import numpy as np
import torch

torch.set_num_threads(2)
root = Path('/kaggle/working')
info = {'python': sys.version, 'platform': platform.platform(), 'torch': str(torch.__version__),
        'numpy': np.__version__, 'cuda_runtime': torch.version.cuda, 'cpu_count': os.cpu_count(),
        'ram': Path('/proc/meminfo').read_text().splitlines()[:3],
        'free_working_bytes': shutil.disk_usage(root).free, 'accelerators': [],
        'purpose': 'Hardware-only preflight; random tensors do not train or export a detector',
        'internet_requested': False, 'requested_timeout_seconds': 600}
for i in range(torch.cuda.device_count()):
    p = torch.cuda.get_device_properties(i)
    info['accelerators'].append({'index': i, 'name': p.name, 'vram_bytes': p.total_memory,
                                 'capability': list(torch.cuda.get_device_capability(i))})
if not info['accelerators']:
    raise RuntimeError('CUDA GPU was not provisioned')
torch.cuda.set_device(0)
net = torch.nn.GRU(64, 64, batch_first=True).cuda()
optimizer = torch.optim.Adam(net.parameters(), lr=0.001)
sample = torch.randn(128, 520, 64, device='cuda')
bench = []
for amp in (False, True):
    torch.cuda.reset_peak_memory_stats()
    torch.cuda.synchronize()
    begin = time.monotonic()
    for _ in range(12):
        optimizer.zero_grad(set_to_none=True)
        with torch.autocast('cuda', dtype=torch.float16, enabled=amp):
            output, _ = net(sample)
            loss = output[:, -1].float().square().mean()
        loss.backward()
        optimizer.step()
    torch.cuda.synchronize()
    elapsed = time.monotonic() - begin
    bench.append({'fp16': amp, 'step_seconds': elapsed / 12,
                  'examples_per_second': 128 * 12 / elapsed,
                  'peak_vram_bytes': torch.cuda.max_memory_allocated(),
                  'finite_loss': bool(torch.isfinite(loss))})
info['gru_synthetic_benchmark'] = bench
info['gpu_status'] = subprocess.check_output(['nvidia-smi', '--query-gpu=name,memory.total,memory.used,utilization.gpu',
                                             '--format=csv,noheader'], text=True).strip()
info['elapsed_seconds'] = time.monotonic() - started
(root / 'xran-preflight.json').write_text(json.dumps(info, indent=2))
print(json.dumps(info, indent=2))
