FROM gcr.io/distroless/static-debian12:nonroot

COPY nazar /usr/local/bin/nazar

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/nazar"]
