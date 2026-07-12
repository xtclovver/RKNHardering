package com.notcvnt.rknhardering.probe.privileged;

interface IPrivilegedProbeService {
    boolean openSession(in byte[] nonce) = 1;
    int getProtocolVersion(in byte[] nonce) = 2;
    int getProviderUid(in byte[] nonce) = 3;
    String[] probeWireGuard(in byte[] nonce) = 4;
    String[] probeOvpn(in byte[] nonce) = 5;
    String[] probeXfrm(in byte[] nonce, boolean imsContext) = 6;
    String[] probeBpfNetfilter(in byte[] nonce) = 7;
    void closeSession(in byte[] nonce) = 8;
    void cancelSession(in byte[] nonce) = 9;
    void destroy() = 16777114;
}
