#ifndef RBAC_SYSTEM_H
#define RBAC_SYSTEM_H
#include <stdbool.h>

typedef struct RoleNode RoleNode;
RoleNode* init_rbac_system();
void add_sub_role(RoleNode* parent, RoleNode* child);
bool check_access(RoleNode* root, const char* current_role, const char* required_perm);
void free_rbac_tree(RoleNode* root);

#endif
