from counterfit.core.attacks import Attack
from numpy import random
from .PEutils.secml_attacks import SecMLGammaShift

class PEGammaAttack(Attack):
    attack_cls = SecMLGammaShift
    attack_name = "secml_gamma_shift"
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
        "population_size": 15,
        "penalty_regularizer": 1e-7,
        "threshold": 0,
        "iterations": 500,
        "sections": 5
    }