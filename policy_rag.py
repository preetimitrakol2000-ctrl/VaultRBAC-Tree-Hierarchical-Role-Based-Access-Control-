import numpy as np
from rbac_bridge import RbacBridge

class PolicyRAG:
    def __init__(self):
        self.kb = [
            {"query": "database:read denied", "recommendation": "Elevate to DataEngineer role or append temporary read-only token to session contextual bounds."},
            {"query": "network:reboot denied", "recommendation": "Critical Infrastructure action. Enforce Multi-Party Authorization verification pipelines."},
        ]
        self.vocab = list(set(" ".join([d["query"] for d in self.kb]).lower().split()))
        self.vector_store = [self._embed(doc["query"]) for doc in self.kb]

    def _embed(self, text: str) -> np.ndarray:
        tokens = text.lower().split()
        return np.array([tokens.count(word) for word in self.vocab], dtype=float)

    def retrieve_remediation(self, breach_context: str):
        q_vec = self._embed(breach_context)
        best_score, best_doc = -1, None
        for idx, doc_vec in enumerate(self.vector_store):
            dot = np.dot(q_vec, doc_vec)
            norm = (np.linalg.norm(q_vec) * np.linalg.norm(doc_vec))
            score = dot / norm if norm else 0.0
            if score > best_score:
                best_score, best_doc = score, self.kb[idx]
        return best_doc["recommendation"] if best_doc else "Generate dynamic policy overrides manually."

if __name__ == "__main__":
    rbac = RbacBridge()
    rag = PolicyRAG()
    
    test_role = "GuestIntern"
    req_perm = "database:read"
    
    is_allowed = rbac.verify_permission(test_role, req_perm)
    if not is_allowed:
        context_string = f"{req_perm} denied"
        fix = rAG.retrieve_remediation(context_string)
        print(f"[ACCESS DENIED] Role '{test_role}' missing verification for target '{req_perm}'.")
        print(f"[RAG Remediation Engine Advice]: {fix}")
