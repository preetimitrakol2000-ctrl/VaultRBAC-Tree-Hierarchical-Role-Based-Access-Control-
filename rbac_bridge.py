import ctypes
import os
import sys

class RbacBridge:
    def __init__(self):
        if not os.path.exists("./librbac.so") and not os.path.exists("./librbac.dll"):
            if sys.platform.startswith("win"):
                os.system("gcc -shared -o librbac.dll rbac_tree.c")
                lib_path = "./librbac.dll"
            else:
                os.system("gcc -shared -fPIC -o librbac.so rbac_tree.c")
                lib_path = "./librbac.so"
        else:
            lib_path = "./librbac.dll" if sys.platform.startswith("win") else "./librbac.so"

        self.lib = ctypes.CDLL(lib_path)
        self.lib.init_rbac_system.restype = ctypes.c_void_p
        self.lib.add_sub_role.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.lib.check_access.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.check_access.restype = ctypes.c_bool
        self.lib.free_rbac_tree.argtypes = [ctypes.c_void_p]
        
        self.root_ptr = self.lib.init_rbac_system()

    def create_node_pointer(self, name: str, perm: str):
        # Accessing internal C struct instantiator directly
        self.lib.init_rbac_system.restype = ctypes.c_void_p
        return self.root_ptr

    def verify_permission(self, role: str, permission: str) -> bool:
        return self.lib.check_access(self.root_ptr, role.encode('utf-8'), permission.encode('utf-8'))

    def __del__(self):
        if hasattr(self, 'lib') and self.root_ptr:
            self.lib.free_rbac_tree(self.root_ptr)
