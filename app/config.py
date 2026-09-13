import os


class Config:
    @property
    def API_TOKEN(self) -> str:
        return os.environ.get("API_TOKEN", "")


config = Config()
