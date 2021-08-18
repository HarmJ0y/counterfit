import os
import numpy as np
from counterfit.core import config
from counterfit.core.state import CFState

from secml.array import CArray
from secml_malware.attack.blackbox.c_wrapper_phi import CEmberWrapperPhi
from secml_malware.models import CClassifierEmber

from secml_malware.attack.blackbox.ga.c_base_genetic_engine import CGeneticAlgorithm
from secml_malware.attack.blackbox.c_gamma_sections_evasion import CGammaSectionsEvasionProblem
from secml_malware.attack.blackbox.c_gamma_shift_problem import CGammaShiftEvasionProblem

from secml_malware.attack.blackbox.c_blackbox_header_problem import CBlackBoxHeaderEvasionProblem

def print_config(type=None, model_endpoint=None, goodware=None, kwargs=None):
        print(f"\n[!] {type} config:")
        print("\ttarget model: ", model_endpoint)
        _ = [print(f"\t{x}: ", kwargs[x]) for x in kwargs.keys()]
        """
        print("\tnumber of sections to be added: ", kwargs["sections"])
        print("\tpopulation_size: ", kwargs["population_size"])
        print("\tpenalty_regularizer: ", kwargs["penalty_regularizer"])
        print("\titerations: ", kwargs["iterations"])
        print("\tthreshold: ", kwargs["threshold"])
        """
        if goodware:
            print("\tgoodware folder and contents:\n\t\t", goodware+"/")
            _ = [print("\t\t",x) for x in os.listdir(goodware)]
        print()



class SecML_DOS:
    # running attacks against only ember for now
    model_endpoint = os.path.join(
        config.targets_path, 'ember/ember_model.txt') # gzip -c -d counterfit/tagets/ember/ember_model.txt.gz > counterfit/tagets/ember/ember_model.txt

    def __init__(self, *args, **kwargs):
        
        model = CClassifierEmber(self.model_endpoint)
        self.ember_model = CEmberWrapperPhi(model)
        
        self.attack = CBlackBoxHeaderEvasionProblem(
                    self.ember_model, 
                    population_size=kwargs["population_size"], 
                    optimize_all_dos=kwargs["optimize_all_dos"],
                    iterations=kwargs["iterations"], 
                    penalty_regularizer=kwargs["penalty_regularizer"]
                )

        print_config(type="DOS header manipulation", model_endpoint=self.model_endpoint, kwargs=kwargs)

    def generate(self, x, y=None):
        adversarial_samples = []

        for i, sample in enumerate(x):
            # CArray - secml's type, needed for sec_ml's ember.predict
            byte_array = CArray(np.frombuffer(sample, dtype='uint8')).atleast_2d()
            _, ember_confidence = self.ember_model.predict(byte_array, return_decision_function=True)
            y = ember_confidence.atleast_2d().tondarray()[0, 1].item()
            
            try:
                j = CFState.get_instance().active_target.active_attack.sample_index[i]
            except TypeError:
                j = CFState.get_instance().active_target.active_attack.sample_index

            print(f"[*] Executing DOS header manipulation attack on sample index {j}...")
            
            engine = CGeneticAlgorithm(self.attack)
            y_pred, adv_score, adv_ds, f_obj = engine.run(byte_array, y)
            
            # re-evaluation & reporting
            _, ember_confidence = self.ember_model.predict(adv_ds.X, return_decision_function=True)
            print("[!] Results on Ember:")
            print(f"\tBefore DOS manipulations: {y}")
            print(f"\tAfter DOS manipulations: {ember_confidence.atleast_2d().tondarray()[0, 1].item()}")

            adv_Xnd = adv_ds.X[0,:].tondarray()
            adversarial_samples.append(adv_Xnd)

        return adversarial_samples
    

class SecMLGammaShift:
    model_endpoint = os.path.join(
        config.targets_path, 'ember/ember_model.txt') # gzip -c -d counterfit/tagets/ember/ember_model.txt.gz > counterfit/tagets/ember/ember_model.txt
    

    def __init__(self, *args, **kwargs):

        model = CClassifierEmber(self.model_endpoint)
        self.ember_model = CEmberWrapperPhi(model)

        goodware = os.path.join(config.attacks_path, "mlsecevade/PEutils/goodware")
        section_population, what_from_who = CGammaSectionsEvasionProblem.\
                                                create_section_population_from_folder(
                                                    goodware, 
                                                    how_many=kwargs["sections"], 
                                                    sections_to_extract=['.rdata']
                                                )
        
        self.attack = CGammaShiftEvasionProblem(
                    section_population, 
                    self.ember_model, 
                    population_size=kwargs["population_size"], 
                    penalty_regularizer=kwargs["penalty_regularizer"], 
                    iterations=kwargs["iterations"], 
                    threshold=kwargs["threshold"]
                )

        print_config(type="GAMMA shift", model_endpoint=self.model_endpoint, kwargs=kwargs, goodware=goodware)
    
    def generate(self, x, y=None):
        adversarial_samples = []

        for i, sample in enumerate(x):
            # CArray - secml's type, needed for sec_ml's ember.predict
            byte_array = CArray(np.frombuffer(sample, dtype='uint8')).atleast_2d()
            _, ember_confidence = self.ember_model.predict(byte_array, return_decision_function=True)
            y = ember_confidence.atleast_2d().tondarray()[0, 1].item()
            
            try:
                j = CFState.get_instance().active_target.active_attack.sample_index[i]
            except TypeError:
                j = CFState.get_instance().active_target.active_attack.sample_index

            print(f"[*] Executing GAMMA section shift attack on sample index {j}...")
            
            engine = CGeneticAlgorithm(self.attack)
            y_pred, adv_score, adv_ds, f_obj = engine.run(byte_array, y)
            
            # re-evaluation & reporting
            _, ember_confidence = self.ember_model.predict(adv_ds.X, return_decision_function=True)
            print("[!] Results on Ember:")
            print(f"\tBefore GAMMA shift: {y}")
            print(f"\tAfter GAMMA shift: {ember_confidence.atleast_2d().tondarray()[0, 1].item()}")

            adv_Xnd = adv_ds.X[0,:].tondarray()
            adversarial_samples.append(adv_Xnd)

        return adversarial_samples

class SecMLGammaInjection:
    # running attacks against only ember for now
    model_endpoint = os.path.join(
        config.targets_path, 'ember/ember_model.txt') # gzip -c -d counterfit/tagets/ember/ember_model.txt.gz > counterfit/tagets/ember/ember_model.txt
    

    def __init__(self, *args, **kwargs):

        model = CClassifierEmber(self.model_endpoint)
        self.ember_model = CEmberWrapperPhi(model)

        goodware = os.path.join(config.attacks_path, "mlsecevade/PEutils/goodware")
        section_population, what_from_who = CGammaSectionsEvasionProblem.\
                                                create_section_population_from_folder(
                                                    goodware, 
                                                    how_many=kwargs["sections"], 
                                                    sections_to_extract=['.rdata']
                                                )
        
        self.attack = CGammaSectionsEvasionProblem(
                    section_population, 
                    #CFState.get_instance().active_target, 
                    # DOESN'T TAKE FAKE CLASSIFIER, POINTED DIRECTLY TO API :(
                    # NEEDS TO CONTRADICT WITH THIS CLASS:
                    # https://github.com/pralab/secml/blob/master/src/secml/ml/classifiers/c_classifier.py#L19
                    self.ember_model, 
                    population_size=kwargs["population_size"], 
                    penalty_regularizer=kwargs["penalty_regularizer"], 
                    iterations=kwargs["iterations"], 
                    threshold=kwargs["threshold"]
                )

        print_config(type="GAMMA injection", model_endpoint=self.model_endpoint, kwargs=kwargs, goodware=goodware)

    def generate(self, x, y=None):
        adversarial_samples = []

        for i, sample in enumerate(x):
            # CArray - secml's type, needed for sec_ml's ember.predict
            byte_array = CArray(np.frombuffer(sample, dtype='uint8')).atleast_2d()
            _, ember_confidence = self.ember_model.predict(byte_array, return_decision_function=True)
            y = ember_confidence.atleast_2d().tondarray()[0, 1].item()
            
            try:
                j = CFState.get_instance().active_target.active_attack.sample_index[i]
            except TypeError:
                j = CFState.get_instance().active_target.active_attack.sample_index

            print(f"[*] Executing GAMMA section injection attack on sample index {j}...")
            
            engine = CGeneticAlgorithm(self.attack)
            y_pred, adv_score, adv_ds, f_obj = engine.run(byte_array, y)
            
            # re-evaluation & reporting
            _, ember_confidence = self.ember_model.predict(adv_ds.X, return_decision_function=True)
            print("[!] Results on Ember:")
            print(f"\tBefore GAMMA section injection: {y}")
            print(f"\tAfter GAMMA section injection: {ember_confidence.atleast_2d().tondarray()[0, 1].item()}")

            adv_Xnd = adv_ds.X[0,:].tondarray()
            adversarial_samples.append(adv_Xnd)

        return adversarial_samples
