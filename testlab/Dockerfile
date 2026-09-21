FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 sudo findutils procps libcap2-bin && rm -rf /var/lib/apt/lists/*

# Low-privilege test user
RUN useradd -m -s /bin/bash lowpriv

# --- Vector 1: SUID python3 (classic GTFOBins SUID escalation) ---
RUN mkdir -p /opt/vulnapp && cp /usr/bin/python3.11 /opt/vulnapp/python3 \
    && chown root:root /opt/vulnapp/python3 \
    && chmod 4755 /opt/vulnapp/python3

# --- Vector 2: passwordless sudo on `find` (classic GTFOBins sudo escalation) ---
RUN echo "lowpriv ALL=(root) NOPASSWD: /usr/bin/find" > /etc/sudoers.d/lowpriv-find \
    && chmod 440 /etc/sudoers.d/lowpriv-find

# --- Vector 3: cap_setuid capability on python3 (classic GTFOBins capability escalation) ---
# basename must be exactly "python3" for the GTFOBins lookup to match - use a
# separate directory so it doesn't collide with the SUID copy above.
RUN mkdir -p /opt/vulnapp2 && cp /usr/bin/python3.11 /opt/vulnapp2/python3 \
    && setcap cap_setuid,cap_setgid+ep /opt/vulnapp2/python3

# --- Vector 4 (negative control): mount is SUID by default, should NOT be flagged ---
# (no action needed, mount is already setuid root out of the box)

COPY confirmesc.pyz /home/lowpriv/confirmesc.pyz
RUN chown lowpriv:lowpriv /home/lowpriv/confirmesc.pyz && chmod +x /home/lowpriv/confirmesc.pyz

USER lowpriv
WORKDIR /home/lowpriv
CMD ["/bin/bash"]
