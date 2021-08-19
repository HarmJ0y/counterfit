from counterfit.core.attacks import Attack
from numpy import random
from .PEutils.secml_attacks import SecML_header_whitebox

class PEGammaAttack(Attack):
    attack_cls = SecML_header_whitebox
    attack_name = "secml_header"
    attack_type = "evasion"
    tags =["pe"]
    category = "whitebox"
    framework = "secml"

    random = {
        "optimize_all_dos": bool(random.binomial(1,0.5)),
        "iterations": random.uniform(1, 500),
        "threshold": random.uniform(0, 1)
    }

    default = {
        "optimize_all_dos": False,
        "iterations": 100,
        "threshold": 0
    }