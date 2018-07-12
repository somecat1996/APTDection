# -*- coding: utf-8 -*-


import os
import xml.etree.ElementTree


ROOT = os.path.dirname(os.path.abspath(__file__))


def parse():
    file = os.path.join(ROOT, 'allagents.xml')
    root = xml.etree.ElementTree.parse(file).getroot()

    ua = dict()
    for element in root:
        ua[element[1].text] = dict(
            desc = element[2].text,
            type = element[3].text,
            comment = element[4].text,
            link = (element[5].text, element[6].text),
        )

    return ua
