#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
import struct

from utils.utils import getBits

class BufferError(Exception):
    pass


class Buffer(object):

    """
    A simple data buffer
    supports packing/unpacking in struct format 

    >>> def p(s):
    ...     if not isinstance(s,str):
    ...         return s.decode()
    ...     return s
    >>> b = Buffer()
    >>> b.pack("!BHI",1,2,3)
    >>> b.offset
    7
    >>> b.append(b"0123456789")
    >>> b.offset
    17
    >>> p(b.hex())
    '0100020000000330313233343536373839'
    >>> b.offset = 0
    >>> b.unpack("!BHI")
    (1, 2, 3)
    >>> bytearray(b.get(5))
    bytearray(b'01234')
    >>> bytearray(b.get(5))
    bytearray(b'56789')
    >>> b.update(7,"2s",b"xx")
    >>> b.offset = 7
    >>> bytearray(b.get(5))
    bytearray(b'xx234')
    """

    def __init__(self, data=b''):
        """
        Initialise Buffer from data
        """
        self.data = data
        self.offset = 0

    def remaining(self):
        """
        Return bytes remaining
        """
        return len(self.data) - self.offset

    def get(self, length):
        """
        Gen len bytes at current offset (& increment offset)
        """
        if length > self.remaining():
            raise BufferError("Not enough bytes [remaining=%d,requested=%d]" %
                              (self.remaining(), length))
        start = self.offset
        end = self.offset + length
        self.offset += length
        return self.data[start:end]

    def getremain(self):
        start = self.offset
        return self.data[start:]

    def hex(self):
        """
        Return data as hex string
        """
        return binascii.hexlify(self.data)

    def pack(self, fmt, *args):
        """
        Pack data at end of data 
        according to fmt (from struct) 
        and increment offset
        """
        self.offset += struct.calcsize(fmt)
        self.data += struct.pack(fmt, *args)

    def append(self, s):
        """
        Append s to end of data and increment offset
        """
        self.offset += len(s)
        self.data += s

    def update(self, ptr, fmt, *args):
        """
        Modify data at offset `ptr` 
        """
        s = struct.pack(fmt, *args)
        self.data[ptr:ptr+len(s)] = s

    def unpack(self, fmt):
        """
        Unpack data at current offset according to fmt (from struct)
        """
        try:
            data = self.get(struct.calcsize(fmt))
            return struct.unpack(fmt, data)
        except struct.error as e:
            raise BufferError("Error unpacking struct '%s' <%s>" %
                              (fmt, binascii.hexlify(data).decode()))

    def decodeName(self, last=-1):
        """
        Decode label at current offset in buffer 
        (following pointers to cached elements where necessary)
        """
        label = []
        done = False
        while not done:
            (length,) = self.unpack("!B")
            if getBits(length, 6, 2) == 3:
                # Pointer
                self.offset -= 1
                pointer = getBits(self.unpack("!H")[0], 0, 14)
                save = self.offset
                if last == save:
                    raise BufferError("Recursive pointer in DNSLabel [offset=%d,pointer=%d,length=%d]" %
                                      (self.offset, pointer, len(self.data)))
                if pointer < self.offset:
                    self.offset = pointer
                else:
                    # Pointer can't point forwards
                    raise BufferError("Invalid pointer in DNSLabel [offset=%d,pointer=%d,length=%d]" %
                                      (self.offset, pointer, len(self.data)))
                label.extend(self.decodeName(save).label)
                self.offset = save
                done = True
            else:
                if length > 0:
                    l = self.get(length)
                    try:
                        l.decode()
                    except UnicodeDecodeError:
                        raise BufferError("Invalid label <%s>" % l)
                    label.append(l)
                else:
                    done = True
        return ".".join(label)

    def __repr__(self):
        return repr(self.data)

    def __len__(self):
        return len(self.data)

    def __getitem__(self, i):
        return self.data[i]

if __name__ == '__main__':
    import doctest
    doctest.testmod()
