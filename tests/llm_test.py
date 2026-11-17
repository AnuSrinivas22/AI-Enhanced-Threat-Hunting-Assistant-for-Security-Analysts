
import ollama

MODEL_NAME = "llama3.2:3b"

print("\n===== LOCAL LLM TEST STARTED =====")
print(f"Model: {MODEL_NAME}")

try:
    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {
                "role": "user",
                "content": "Explain what a DDoS attack is in two simple sentences."
            }
        ]
    )

    print("\n===== LLM TEST RESULT =====")
    print(response["message"]["content"])
    print("\n===== LOCAL LLM TEST PASSED =====")

except Exception as error:
    print("\n===== LOCAL LLM TEST FAILED =====")
    print("Error:", error)
    print("Check that Ollama is running and llama3.2:3b is installed.")