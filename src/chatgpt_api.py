import openai
import openai.error
from typing import List, Dict, Optional
import os
import requests
from config import GPT4_API, LLM_PROVIDER, OPENAI_MODEL, OPENAI_GPT4_MODEL, OLLAMA_MODEL, OLLAMA_BASE_URL
import logging
import time
import traceback
import tiktoken
from multiprocessing import Value
import rich
import rich_utils
logger = logging.getLogger(__name__)

console = rich.get_console()

SYSTEM_MESSAGE = "You are a smart contract auditor. You will be asked questions related to code properties. You can mimic answering them in the background five times and provide me with the most frequently appearing answer. Furthermore, please strictly adhere to the output format specified in the question; there is no need to explain your answer."

encoder = tiktoken.get_encoding("cl100k_base")
encoder = tiktoken.encoding_for_model("gpt-3.5-turbo")

tokens_sent = Value("d", 0)
tokens_received = Value("d", 0)
tokens_sent_gpt4 = Value("d", 0)
tokens_received_gpt4 = Value("d", 0)


class OllamaAPIError(Exception):
    pass


class Chat:
    def __init__(self) -> None:
        self.currentSession:List[Dict[str,str]] = []
    
    def newSession(self) -> None:
        self.currentSession = []

    def _resolve_runtime_config(self, GPT4: bool) -> Dict[str, str]:
        provider = os.getenv("GPTSCAN_LLM_PROVIDER", LLM_PROVIDER).strip().lower()
        if provider not in {"openai", "ollama"}:
            provider = "openai"

        configured_model = os.getenv("GPTSCAN_LLM_MODEL", "").strip()
        configured_gpt4_model = os.getenv("GPTSCAN_LLM_MODEL_GPT4", "").strip()
        ollama_base_url = os.getenv("GPTSCAN_OLLAMA_URL", OLLAMA_BASE_URL).strip().rstrip("/")

        if GPT4:
            default_model = configured_gpt4_model or OPENAI_GPT4_MODEL
        elif provider == "ollama":
            default_model = configured_model or OLLAMA_MODEL
        else:
            default_model = configured_model or OPENAI_MODEL

        return {
            "provider": provider,
            "model": default_model,
            "ollama_base_url": ollama_base_url,
        }

    def _send_openai_message(self, model: str, GPT4: bool):
        if GPT4:
            openai.api_key = GPT4_API

        response = openai.ChatCompletion.create(
            model=model,
            messages=self.currentSession,
            temperature=0,
            top_p=1.0,
        )
        return response['choices'][0]['message']['content']

    def _send_ollama_message(self, base_url: str, model: str, timeout_seconds: Optional[int] = None) -> str:
        if timeout_seconds is None:
            try:
                timeout_seconds = int(os.environ.get("GPTSCAN_OLLAMA_TIMEOUT", "60"))
            except Exception:
                timeout_seconds = 60

        attempts = 0
        max_attempts = 3
        last_exc = None
        while attempts < max_attempts:
            attempts += 1
            try:
                response = requests.post(
                    f"{base_url.rstrip('/')}/api/chat",
                    json={
                        "model": model,
                        "messages": self.currentSession,
                        "stream": False,
                        "options": {
                            "temperature": 0,
                            "top_p": 1.0,
                        },
                    },
                    timeout=timeout_seconds,
                )
                response.raise_for_status()
                payload = response.json()
                return payload.get("message", {}).get("content", "")
            except requests.HTTPError as e:
                status_code = e.response.status_code if e.response is not None else None
                logger.warning("Ollama HTTP error (attempt %d/%d): %s", attempts, max_attempts, status_code)
                last_exc = e
                if status_code is not None and 500 <= status_code <= 599:
                    time.sleep(1)
                    continue
                if status_code == 429:
                    time.sleep(3)
                    continue
                raise
            except requests.RequestException as e:
                logger.warning("Ollama request exception (attempt %d/%d): %s", attempts, max_attempts, str(e))
                last_exc = e
                time.sleep(1)
                continue

        # If we reach here, all attempts failed
        logger.error("Ollama API unreachable after %d attempts", max_attempts)
        raise OllamaAPIError(f"Ollama API unreachable: {last_exc}")
    
    def sendMessages(self, message:str, GPT4=False, timeout_seconds: Optional[int] = None, override_ollama_base_url: Optional[str] = None) -> str:

        # logger.info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        # logger.info(f"Sending message: \n{message}")
        # logger.info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        
        self.currentSession.append({"role": "system", "content": SYSTEM_MESSAGE})
        self.currentSession.append({"role": "user", "content": message})

        runtime_config = self._resolve_runtime_config(GPT4)
        provider = runtime_config["provider"]
        model = runtime_config["model"]

        attempts_loop = 0
        while True:
            attempts_loop += 1
            try:
                if provider == "openai":
                    content = self._send_openai_message(model, GPT4)
                else:
                    base = override_ollama_base_url or runtime_config.get("ollama_base_url")
                    content = self._send_ollama_message(base, model, timeout_seconds=timeout_seconds)
                    if content == "":
                        logger.warning("Empty response from Ollama, retry")
                        if attempts_loop >= 3:
                            raise OllamaAPIError("Empty response from Ollama after retries")
                        continue
                break
            except openai.error.RateLimitError as e1:
                logger.warning("Trigger rate limit error, sleep 30 sec")
                time.sleep(30)
            except openai.InvalidRequestError as e2:
                if e2.code == 'context_length_exceeded':
                    logger.error("Too long context, skip")
                    return "KeySentence: "
                else:
                    logger.warning("Retry")
            except openai.error.APIConnectionError as e3:
                logger.warning("API Connection Error, Retry")
            except openai.error.Timeout as e4:
                logger.warning("Timeout, Retry")
            except openai.error.APIError as e5:
                if "502" in e5._message:
                    logger.warning("502 Bad Gateway, Retry")
                    logger.warning(traceback.format_exc())
            except requests.HTTPError as e6:
                status_code = e6.response.status_code if e6.response is not None else None
                if status_code == 429:
                    logger.warning("Ollama rate limited, sleep 3 sec")
                    time.sleep(3)
                    continue
                if status_code is not None and 500 <= status_code <= 599:
                    logger.warning("Ollama server error, retry")
                    time.sleep(1)
                    continue
                logger.error("Ollama HTTP error")
                logger.error(traceback.format_exc())
                return "KeySentence: "
            except requests.RequestException:
                logger.warning("Ollama request error, retry")
                time.sleep(1)
            except OllamaAPIError:
                logger.error("Ollama persistent failure, aborting sendMessages")
                return "KeySentence: "
            except Exception as ex:
                logger.warning("Unexpected error in sendMessages: %s", str(ex))
                time.sleep(1)
                continue
        #     # model="gpt-3.5-turbo",
        #     model="text-davinci-003",
        #     messages = self.currentSession,
        #     # temperature = 0.3
        # )

        if GPT4:
            global tokens_sent_gpt4
            global tokens_received_gpt4

            tokens_sent_gpt4.value += len(encoder.encode(SYSTEM_MESSAGE))
            tokens_sent_gpt4.value += len(encoder.encode(message))
            tokens_received_gpt4.value += len(encoder.encode(content))
        else:
            global tokens_sent
            global tokens_received

            tokens_sent.value += len(encoder.encode(SYSTEM_MESSAGE))
            tokens_sent.value += len(encoder.encode(message))
            tokens_received.value += len(encoder.encode(content))

        assistant_message = {"role": "assistant", "content": content}
        self.currentSession.append(assistant_message)

        console.print(rich_utils.make_response_panel(content, "Response"))
        
        return content
    
    def makeYesOrNoQuestion(self, question:str)->str:
        prompt = f"{question}. Please answer in one word, yes or no."
        return prompt
    
    def makeCodeQuestion(self, question:str, code:str):
        prompt = f'Please analyze the following code, and answer the question "{question}"\n{code}'
        return prompt
