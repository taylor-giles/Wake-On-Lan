__all__ = ['logger']


import logging
import click
from copy import copy
import sys
from typing import Optional, Literal


class ColorFormatter(logging.Formatter):
    level_name_colors = {
        logging.DEBUG: lambda level_name: click.style(str(level_name), fg="green"),
        logging.INFO: lambda level_name: click.style(str(level_name), fg="bright_cyan"),
        logging.WARNING: lambda level_name: click.style(str(level_name), fg="bright_yellow"),
        logging.ERROR: lambda level_name: click.style(str(level_name), fg="red"),
        logging.CRITICAL: lambda level_name: click.style(str(level_name), fg="bright_red"),
    }

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        style: Literal["%", "{", "$"] = "%",
        use_colors: Optional[bool] = None,
    ):
        if use_colors in (True, False):
            self.use_colors = use_colors
        else:
            self.use_colors = sys.stdout.isatty()
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)

    def color_level_name(self, level_name: str, level_no: int) -> str:
        def default(level_name: str) -> str:
            return str(level_name)

        func = self.level_name_colors.get(level_no, default)
        return func(level_name)

    def quick_style(self, value, color):
        return click.style(str(value), fg=color)

    def formatMessage(self, record: logging.LogRecord) -> str:
        recordcopy = copy(record)
        levelname = recordcopy.levelname
        seperator = " " * (8 - len(recordcopy.levelname))
        if self.use_colors:
            levelname = self.color_level_name(levelname, recordcopy.levelno)
            recordcopy.__dict__["process"] = self.quick_style(recordcopy.process, 'magenta')
            if "color_message" in recordcopy.__dict__:
                recordcopy.msg = recordcopy.__dict__["color_message"]
                recordcopy.__dict__["message"] = recordcopy.getMessage()
        recordcopy.__dict__["levelprefix"] = seperator + levelname
        recordcopy.__dict__["location"] = "%30s" % (recordcopy.module + "::" + recordcopy.funcName)
        return super().formatMessage(recordcopy)


rychlyLogFormatter = ColorFormatter(
    "[{asctime}][{process}][{location}][{levelprefix}]: {message}",
    style='{',
    use_colors=True
)


# Format the Uvicorn Loggers
loggers = [ logging.getLogger("uvicorn"), logging.getLogger("uvicorn.access") ]

for _logger in loggers:
    _logger.handlers[0].setFormatter(rychlyLogFormatter)

# The official logger
logger = logging.getLogger("uvicorn")

logger.setLevel("DEBUG")
