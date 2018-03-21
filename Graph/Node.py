from ContentType import ContentType


class Node:
    '''A node class.'''
    def __init__(self, Host, Uri, Type, Body=None):
        self.parent = None
        #None means this is a head node
        self.children = []
        #Empty means this node does not have child node
        self.host = Host
        self.uri = Uri
        self.type = ContentType(Type)
        self.body = Body
        #Ignore all bodies except text/html and text/css type

    def SetParent(self, Parent):
        self.parent = Parent

    def AddChild(self, Child):
        self.children.append(Child)
