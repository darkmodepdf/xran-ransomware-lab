"""Verify shipped model artifacts; optional research-profile CPU load smoke."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from raneval.windows_stream import Model


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--load-endpoint',action='store_true')
    args=parser.parse_args()
    registry=json.loads((ROOT/'models/manifest.json').read_text())
    native=json.loads((ROOT/registry['native_model']).read_text())
    assert native['sha256']==registry['native_payload_sha256'],'Native payload differs from registry'
    Model(native)
    for path in ('demo/windows_streaming/model.json','demo/windows_streaming/native-model-v1.json'):
        Model(ROOT/path)
    checked=0
    for entry in registry['endpoint']:
        directory=(ROOT/entry['path']).resolve()
        if not directory.is_relative_to((ROOT/'models/xran-endpoint').resolve()):
            raise ValueError('Model path escaped registry directory')
        for name,expected in entry['files'].items():
            path=(directory/name).resolve()
            if path.parent!=directory:raise ValueError('Model filename escaped directory')
            content=path.read_bytes()
            assert len(content)==expected['bytes'],f'{entry["id"]}/{name}: size mismatch'
            assert hashlib.sha256(content).hexdigest()==expected['sha256'],f'{entry["id"]}/{name}: hash mismatch'
            checked+=1
        if args.load_endpoint:
            import numpy as np
            from raneval.xran_models import load_bundle,predict_endpoint
            bundle=load_bundle(directory)
            scores=predict_endpoint(np.ones((1,520),dtype=np.int64),bundle)
            assert len(scores)==1 and np.isfinite(scores).all(),'Endpoint inference smoke failed'
    print(json.dumps(dict(native_bundles_verified=3,endpoint_files_verified=checked,
                          endpoint_load_smoke=args.load_endpoint,native_payload_sha256=native['sha256']),indent=2))


if __name__=='__main__':main()
