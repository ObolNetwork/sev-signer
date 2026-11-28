.PHONY: clean ovmf-image ovmf measure image image-measure image-test kernel docker-image out-dir kernel-checksum just-kernel just-initramfs provision-installer run-installer

clean:
	rm -rf out/*

# Superseded by the mkosi image (`make image`, image/README.md). The Alpine
# kernel, installer and provisioning targets below are kept for reference only.
docker-image:
	docker build -t obolnetwork/alpine-sev-builder .

out-dir:
	mkdir -p out
	chmod 777 out

kernel-checksum: out-dir docker-image
	docker run -it --rm -v $(PWD)/out:/src/out obolnetwork/alpine-sev-builder:latest checksum

kernel: out-dir docker-image
	docker run -it --rm -v $(PWD)/out:/src/out obolnetwork/alpine-sev-builder:latest complete

just-kernel: out-dir docker-image	
	docker run -it --rm -v $(PWD)/out:/src/out obolnetwork/alpine-sev-builder:latest

just-initramfs: out-dir docker-image
	docker run -it --rm -v $(PWD)/out:/src/out obolnetwork/alpine-sev-builder:latest initramfs

provision-installer:
	cd vm-scripts
	bash provision-installer.sh
	cd ..

run-installer:
	cd vm-scripts
	bash run-installer.sh
	cd ..

ovmf-image:
	docker build -t obolnetwork/ovmf-builder ovmf

# OVMF for SNP guests, built reproducibly from pinned edk2 (ovmf/README.md).
ovmf: ovmf-image
	mkdir -p out/ovmf
	docker run --rm -v $(PWD)/out/ovmf:/out obolnetwork/ovmf-builder

# Expected launch measurement of the old guest run.sh starts (superseded by image-measure).
measure: ovmf-image
	vm-scripts/measure.sh

# Guest image (image/README.md). Needs SNP_MIN_TCB, see docs/hardware-runbook.md.
image:
	image/build.sh

# Expected launch measurement of out/image/dvtee.efi with out/ovmf/OVMF.fd.
image-measure: ovmf-image
	scripts/expected-measurement.sh --json

# Unit tests for the guest's boot scripts (no VM needed).
image-test:
	image/tests/run.sh
