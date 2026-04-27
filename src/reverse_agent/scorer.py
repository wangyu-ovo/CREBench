"""Scoring system that tracks submissions across all 4 evaluation levels."""

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class LevelResult:
    score: int = 0
    max_score: int = 25
    submitted: bool = False
    submission: Optional[Any] = None  # last submission content
    explanation: str = ""
    submit_count: int = 0  # how many times the agent submitted for this level
    submit_step: Optional[int] = None  # deprecated alias for round, kept for compatibility
    round: Optional[int] = None  # budgeted round number of last submission
    actually_step: Optional[int] = None  # absolute tool-action index of last submission


@dataclass
class ScoreReport:
    level1_algorithm: LevelResult = field(default_factory=LevelResult)
    level2_key: LevelResult = field(default_factory=LevelResult)
    level3_code: LevelResult = field(default_factory=LevelResult)
    level4_flag: LevelResult = field(default_factory=LevelResult)

    @property
    def total_score(self) -> int:
        return (
            self.level1_algorithm.score
            + self.level2_key.score
            + self.level3_code.score
            + self.level4_flag.score
        )

    @property
    def max_total(self) -> int:
        return 100

    def to_dict(self) -> dict:
        d = asdict(self)
        d["total_score"] = self.total_score
        d["max_total"] = self.max_total
        return d

    def save(self, path: Path) -> None:
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info(f"Score report saved to {path}")

    def summary(self) -> str:
        lines = [
            f"=== Score Report ===",
            f"L1 Algorithm:     {self.level1_algorithm.score}/{self.level1_algorithm.max_score}"
            + (f"  ({self.level1_algorithm.explanation})" if self.level1_algorithm.submitted else "  (not submitted)"),
            f"L2 Key Material:  {self.level2_key.score}/{self.level2_key.max_score}"
            + (f"  ({self.level2_key.explanation})" if self.level2_key.submitted else "  (not submitted)"),
            f"L3 Code:          {self.level3_code.score}/{self.level3_code.max_score}"
            + (f"  ({self.level3_code.explanation})" if self.level3_code.submitted else "  (not submitted)"),
            f"L4 Flag:          {self.level4_flag.score}/{self.level4_flag.max_score}"
            + (f"  ({self.level4_flag.explanation})" if self.level4_flag.submitted else "  (not submitted)"),
            f"---",
            f"Total:            {self.total_score}/{self.max_total}",
        ]
        return "\n".join(lines)
