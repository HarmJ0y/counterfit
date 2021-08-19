from counterfit.core.attacks import Attack
from numpy import random
from .PEutils.secml_attacks import SecML_DOS

class PEGammaAttack(Attack):
    attack_cls = SecML_DOS
    attack_name = "secml_dos"
    attack_type = "evasion"
    tags =["pe"]
    category = "blackbox"
    framework = "secml"

    random = {
        "population_size": random.randint(5, 15),
        "optimize_all_dos": bool(random.binomial(1,0.5)),
        "iterations": random.uniform(1, 500),
        "penalty_regularizer": random.uniform(1e-5, 1e-4)
    }

    default = {
        "population_size": 10,
        "optimize_all_dos": False,
        "iterations": 100,
        "penalty_regularizer": 1e-6
    }