from counterfit.core.attacks import Attack
from hyperopt import hp
from .PEutils.secml_attacks import SecMLGammaAttack

class PEGammaAttack(Attack):
    attack_cls = SecMLGammaAttack
    attack_name = "secml_gamma"
    attack_type = "evasion"
    tags =["pe"]
    category = "blackbox"
    framework = "mlsecevade"

    random = {
        "population_size": hp.uniform("population_size", 5, 15),
        "penalty_regularizer": hp.uniform("penalty_regularizer", 1e-5, 1e-4),
        "iterations": hp.uniform("iterations", 1, 20),
        "threshold": hp.uniform("threshold", 0, 1),
        # example on choice
        "param": hp.choice("param_conf", [False, True]),
    }

    default = {
        "population_size": 10,
        "penalty_regularizer": 1e-6,
        "threshold": 0,
        "iterations": 10,
        # example
        "param": False
    }