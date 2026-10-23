# DocuSeal 3.3.3, pinned manifest; own API uses the public signing implementation.
FROM docuseal/docuseal@sha256:28d0ca583860e2c73e5b068756023a93a325799a22da1f788355d566865dd051
COPY --chown=docuseal:docuseal signing_api /app/signing_api
WORKDIR /app
ENV RACK_ENV=production
USER root
CMD ["/bin/sh", "/app/signing_api/start.sh"]
