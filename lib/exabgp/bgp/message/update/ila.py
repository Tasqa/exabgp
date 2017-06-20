# encoding: utf-8
"""
ila.py

Created by Arian van Putten & Tako Marks on 2017-06-20.
Copyright (c) 2017 Arian van Putten & Tako Marks. All rights reserved.
"""

from struct import unpack, pack

from exabgp.protocol.family import AFI
from exabgp.protocol.family import SAFI
from exabgp.bgp.message.update.nlri.nlri import NLRI
from exabgp.bgp.message.notification import Notify

@NLRI.register(AFI.ila, SAFI.unicast)
@NLRI.register(AFI.ila, SAFI.multicast)
class ILA (NLRI):
    def __init__(self, safi, identifiers):
        NLRI.__init__(self, AFI.ila, safi)
        self.identifiers = identifiers

    def __eq__ (self,other):
        return self.identifiers == other.identifiers

    def __ne__ (self, other):
        return not self.__eq__(other)

    def __lt__ (self, other):
        raise RuntimeError('comparing identifiers does not make sense')

    def __le__ (self, other):
        raise RuntimeError('comparing identifiers does not make sense')

    def __gt__ (self, other):
        raise RuntimeError('comparing identifiers does not make sense')

    def __ge__ (self, other):
        raise RuntimeError('comparing identifiers does not make sense')

    def __len__ (self):
        return len(self.pack_nlri())

    def __str__ (self):
        return self.extensive()

    def pack_nlri(self, negotiated=None):
        data = b''
        data = data + pack('!H', len(self.identifiers))
        for identifier in self.identifiers:
            data = data + pack('!Q', identifier)
        return data

    @classmethod
    def unpack_nlri (cls, afi, safi, data, action, addpath):
        length = unpack('!H', data[0:2])
        if len(data) != length + 2:
            raise Notify(3,10,'ila message length is not consistent with encoded identifier list')

        identifiers = []
        left = data
        while left:
            identifier = unpack('!Q', left[0:8])[0]
            identifiers.append(identifier)
            left = left[8:]

        return cls(safi, identifiers)
