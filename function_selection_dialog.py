import idaapi
from idaapi import Choose2

class FunctionSelectionDialog(Choose2):
    def __init__(self, title, items):
        Choose2.__init__(self, title, [ ["Match Quality", 10], [ "File", 20 ], ["Function", 20], ["Description", 30], ["Author", 20] ], Choose2.CH_MODAL)
        self.n = 0
        self.items = items
        self.icon = -1
        self.selcount = 0
        self.popup_names = []

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"

    def OnInsertLine(self):
        self.items.append(self.make_item())

    def OnSelectLine(self, n):
        self.selcount += 1
        Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def OnRefresh(self, n):
        return n

    def OnCommand(self, n, cmd_id):
        pass
        
class ModuleSelectionDialog(Choose2):
    def __init__(self, title, items):
        Choose2.__init__(self, title, [ [ "File", 20 ], ["Pieces of Information", 20] ], Choose2.CH_MODAL)
        self.n = 0
        self.items = items
        self.icon = -1
        self.selcount = 0
        self.popup_names = []

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"

    def OnInsertLine(self):
        self.items.append(self.make_item())

    def OnSelectLine(self, n):
        self.selcount += 1
        Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def OnRefresh(self, n):
        return n

    def OnCommand(self, n, cmd_id):
        pass
        
class AllFunctionsSelectionDialog(Choose2):
    def __init__(self, title, items):
        Choose2.__init__(self, title, [ [ "Function", 20 ], ["Count", 20] ], Choose2.CH_MODAL)
        self.n = 0
        self.items = items
        self.icon = -1
        self.selcount = 0
        self.popup_names = []

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"

    def OnInsertLine(self):
        self.items.append(self.make_item())

    def OnSelectLine(self, n):
        self.selcount += 1
        Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def OnRefresh(self, n):
        return n

    def OnCommand(self, n, cmd_id):
        pass
