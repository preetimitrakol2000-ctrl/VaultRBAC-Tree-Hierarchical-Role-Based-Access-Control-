#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_CHILDREN 10

typedef struct RoleNode {
    char role_name[64];
    char permission_token[64];
    struct RoleNode* children[MAX_CHILDREN];
    int child_count;
} RoleNode;

RoleNode* create_role(const char* name, const char* perm) {
    RoleNode* node = (RoleNode*)malloc(sizeof(RoleNode));
    if (node) {
        strncpy(node->role_name, name, sizeof(node->role_name) - 1);
        strncpy(node->permission_token, perm, sizeof(node->permission_token) - 1);
        node->child_count = 0;
        for (int i = 0; i < MAX_CHILDREN; i++) node->children[i] = NULL;
    }
    return node;
}

#ifdef _WIN32
    __declspec(dllexport) RoleNode* init_rbac_system();
    __declspec(dllexport) void add_sub_role(RoleNode* parent, RoleNode* child);
    __declspec(dllexport) bool check_access(RoleNode* root, const char* current_role, const char* required_perm);
    __declspec(dllexport) void free_rbac_tree(RoleNode* root);
#endif

RoleNode* init_rbac_system() {
    return create_role("RootAdmin", "all:write");
}

void add_sub_role(RoleNode* parent, RoleNode* child) {
    if (parent && parent->child_count < MAX_CHILDREN) {
        parent->children[parent->child_count++] = child;
    }
}

// Deep structural traversal to check if a role or any of its inherited child sub-roles contain the policy token
bool check_access(RoleNode* root, const char* current_role, const char* required_perm) {
    if (!root) return false;
    
    if (strcmp(root->role_name, current_role) == 0) {
        if (strcmp(root->permission_token, required_perm) == 0 || strcmp(root->permission_token, "all:write") == 0) {
            return true;
        }
    }
    
    for (int i = 0; i < root->child_count; i++) {
        if (strcmp(root->role_name, current_role) == 0) {
            // Check inheritance pathways downward
            if (strcmp(root->children[i]->permission_token, required_perm) == 0) return true;
        }
        if (check_access(root->children[i], current_role, required_perm)) return true;
    }
    return false;
}

void free_rbac_tree(RoleNode* root) {
    if (!root) return;
    for (int i = 0; i < root->child_count; i++) {
        free_rbac_tree(root->children[i]);
    }
    free(root);
}
