from counterfit.core.attacks import Attack
from numpy import random
from .PEutils.secml_attacks import SecML_padding_whitebox

class PEGammaAttack(Attack):
    attack_cls = SecML_padding_whitebox
    attack_name = "secml_padding"
    attack_type = "evasion"
    tags =["pe"]
    category = "whitebox"
    framework = "secml"

    random = {
        "how_many": random.randint(2048,4096),
        "iterations": random.uniform(1, 500),
        "threshold": random.uniform(0, 1),
        "penalty_regularizer": random.uniform(1e-7, 1e-4)
    }

    default = {
        "how_many": 2096,
        "iterations": 100,
        "threshold": 0,
        "penalty_regularizer": 1e-7
    }