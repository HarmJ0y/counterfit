from counterfit.core.attacks import Attack
from numpy import random
from .PEutils.secml_attacks import SecMLGammaInjection

class PEGammaAttack(Attack):
    attack_cls = SecMLGammaInjection
    attack_name = "secml_gamma_inject"
    attack_type = "evasion"
    tags =["pe"]
    category = "blackbox"
    framework = "mlsecevade"

    random = {
        "population_size": random.randint(5, 15),
        "penalty_regularizer": random.uniform(1e-7, 1e-4),
        "iterations": random.uniform(1, 500),
        "threshold": random.uniform(0, 1),
        "sections": random.randint(2, 10)
    }

    default = {
        "population_size": 10,
        "penalty_regularizer": 1e-6,
        "threshold": 0,
        "iterations": 100,
        "sections": 5
    }