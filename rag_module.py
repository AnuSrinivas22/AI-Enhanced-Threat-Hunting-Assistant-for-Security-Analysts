
import os
import re


class RAGModule:

    def __init__(
        self,
        knowledge_file="knowledge_base/cybersecurity_knowledge.txt"
    ):
        self.knowledge_file = knowledge_file
        self.documents = []
        self.load_error = None

        self.load_knowledge()

        print("RAG Module initialized.")
        print("Knowledge documents loaded:", len(self.documents))

    def load_knowledge(self):
        """Load cybersecurity knowledge from the local knowledge base."""

        self.documents = []
        self.load_error = None

        try:
            if not os.path.exists(self.knowledge_file):
                self.load_error = (
                    f"Knowledge base file not found: {self.knowledge_file}"
                )
                print(self.load_error)
                return

            with open(
                self.knowledge_file,
                "r",
                encoding="utf-8"
            ) as file:
                content = file.read()

            if not content.strip():
                self.load_error = "Knowledge base file is empty."
                print(self.load_error)
                return

            # Split knowledge sections using blank lines
            sections = re.split(r"\n\s*\n+", content)

            for section in sections:

                section = section.strip()

                if section:
                    self.documents.append(section)

            if not self.documents:
                self.load_error = (
                    "No valid knowledge documents were found."
                )
                print(self.load_error)

        except (OSError, UnicodeError, re.error) as e:
            self.load_error = f"Knowledge loading failed: {e}"
            self.documents = []
            print(self.load_error)

    def calculate_similarity(self, query, document):
        """Calculate keyword-based relevance."""

        if not isinstance(query, str):
            raise TypeError("Query must be a string.")

        if not isinstance(document, str):
            raise TypeError("Document must be a string.")

        query_words = set(
            re.findall(r"\b[a-zA-Z0-9]+\b", query.lower())
        )

        document_words = set(
            re.findall(r"\b[a-zA-Z0-9]+\b", document.lower())
        )

        if not query_words:
            return 0.0

        common_words = query_words.intersection(document_words)

        return len(common_words) / len(query_words)

    def retrieve(self, query, top_k=3):
        """Retrieve the most relevant knowledge sections."""

        if not isinstance(query, str):
            raise TypeError("Query must be a string.")

        if not query.strip():
            raise ValueError("Query cannot be empty.")

        if isinstance(top_k, bool) or not isinstance(top_k, int):
            raise TypeError("top_k must be an integer.")

        if top_k < 1:
            raise ValueError("top_k must be at least 1.")

        if not self.documents:
            print("No knowledge documents available.")
            return []

        scored_documents = []

        for document in self.documents:

            score = self.calculate_similarity(
                query,
                document
            )

            scored_documents.append(
                (score, document)
            )

        # Sort by relevance score
        scored_documents.sort(
            key=lambda x: x[0],
            reverse=True
        )

        results = []

        for score, document in scored_documents[:top_k]:

            if score > 0:
                results.append({
                    "score": round(float(score), 3),
                    "content": document
                })

        return results

    def generate_context(
        self,
        threat_type,
        risk_level,
        correlated
    ):
        """Create a retrieval query using multi-agent results."""

        if not isinstance(threat_type, str):
            raise TypeError("Threat type must be a string.")

        if not isinstance(risk_level, str):
            raise TypeError("Risk level must be a string.")

        if not isinstance(correlated, bool):
            raise TypeError("Correlated must be True or False.")

        query = f"""
        {threat_type}
        risk level {risk_level}
        correlated network events {correlated}
        investigation indicators
        mitigation
        """

        return self.retrieve(query, top_k=3)


if __name__ == "__main__":

    print("\n===== RAG MODULE TEST =====")

    try:
        rag = RAGModule()

        results = rag.generate_context(
            threat_type="DDoS",
            risk_level="CRITICAL",
            correlated=True
        )

        print("\n===== RETRIEVED KNOWLEDGE =====")

        if not results:
            print("No relevant knowledge found.")

        else:
            for i, result in enumerate(results, 1):

                print(
                    f"\n[{i}] Relevance Score: "
                    f"{result['score']}"
                )

                print(result["content"])

        print("\n===== RAG TEST COMPLETED =====")

    except Exception as e:
        print(f"RAG test failed: {e}")
