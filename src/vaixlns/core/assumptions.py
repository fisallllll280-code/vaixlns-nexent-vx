"""Assumption registry with auditable mutation."""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Assumption:
    name:str
    claim:str
    confidence:float
    status:str

@dataclass(frozen=True)
class AssumptionMutation:
    name:str
    old_confidence:float
    new_confidence:float
    reason:str

class AssumptionRegistry:
    def __init__(self)->None:
        self._items:dict[str,Assumption]={}

    def register(self, assumption:Assumption)->None:
        if not assumption.name:
            raise ValueError("ASSUMPTION_NAME_REQUIRED")
        self._items[assumption.name]=assumption

    def get(self,name:str)->Assumption:
        return self._items[name]

    def mutate(self,name:str,new_claim:str,new_confidence:float,reason:str)->AssumptionMutation:
        current=self._items[name]
        if not 0.0 <= new_confidence <= 1.0:
            raise ValueError("ASSUMPTION_CONFIDENCE_OUT_OF_RANGE")
        mutation=AssumptionMutation(name,current.confidence,new_confidence,reason)
        self._items[name]=Assumption(name,new_claim,new_confidence,current.status)
        return mutation

__all__=["Assumption","AssumptionMutation","AssumptionRegistry"]
