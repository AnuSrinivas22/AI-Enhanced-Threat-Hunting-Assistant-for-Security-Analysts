import ollama


response = ollama.chat(
    model="llama3.2:3b",
    messages=[
        {
            "role": "user",
            "content": (
                "You are a cybersecurity security analyst. "
                "Explain a DDoS detection result in simple "
                "professional language."
            )
        }
    ]
)


print("\n===== LOCAL LLM TEST =====")
print(response["message"]["content"])
print("\n===== LOCAL LLM TEST COMPLETED =====")