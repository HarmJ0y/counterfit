from counterfit.core.attacks import Attack
from hyperopt import hp
from .PEutils.secml_attacks import SecML_DOS

class PEGammaAttack(Attack):
    attack_cls = SecML_DOS
    attack_name = "secml_dos"
    attack_type = "evasion"
    tags =["pe"]
    category = "blackbox"
    framework = "mlsecevade"

    random = {
        "population_size": hp.uniform("population_size", 5, 15),
        "optimize_all_dos": hp.choice("optimize_all_dos", [False, True]),
        "iterations": hp.uniform("iterations", 1, 500),
        "penalty_regularizer": hp.uniform("penalty_regularizer", 1e-5, 1e-4)
    }

    default = {
        "population_size": 10,
        "optimize_all_dos": False,
        "iterations": 100,
        "penalty_regularizer": 1e-6
    }