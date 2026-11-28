# SUPERSEDED by the mkosi image in image/ (see image/README.md). Kept for reference.
# Pinned by digest (multi-arch index for alpine 3.20.10); Dependabot keeps it current.
# NOTE: Alpine 3.20 reached end of life on 2026-04-01 and no longer gets security
# fixes. Moving the kernel builder to a supported branch needs the APKBUILD to be
# re-validated, so it is tracked separately.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add alpine-sdk doas bash cryptsetup \
    &&  adduser \
    --disabled-password \
    --gecos "" \
    --ingroup "wheel" \
    --uid "1000" \
    builder

# add builder to abuild group
RUN adduser builder abuild

# copy build script and sources in image
COPY build_kernel.sh /build_kernel.sh
COPY linux-mainline-sev-src /src
RUN chown -R builder:wheel /src

# add builder to doas
RUN echo "permit nopass :wheel" >> /etc/doas.conf

USER builder

# create signing key
RUN abuild-keygen -a -i -n

WORKDIR /src

# run the build!
ENTRYPOINT ["sh", "/build_kernel.sh"]
