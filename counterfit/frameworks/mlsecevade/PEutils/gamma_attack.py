import os
import numpy as np
from counterfit.core import config
from counterfit.core.state import CFState

from secml.array import CArray
from secml_malware.attack.blackbox.c_wrapper_phi import CEmberWrapperPhi
from secml_malware.models import CClassifierEmber

from secml_malware.attack.blackbox.ga.c_base_genetic_engine import CGeneticAlgorithm
from secml_malware.attack.blackbox.c_gamma_sections_evasion import CGammaSectionsEvasionProblem

class SecMLGammaAttack:
    # running attacks against only ember for now
    model_endpoint = os.path.join(
        config.targets_path, 'ember/ember_model.txt') # gzip -c -d counterfit/tagets/ember/ember_model.txt.gz > counterfit/tagets/ember/ember_model.txt
    

    def __init__(self, *args, **kwargs):

        model = CClassifierEmber(self.model_endpoint)
        self.ember_model = CEmberWrapperPhi(model)

        goodware = "/home/jovyan/counterfit/counterfit/frameworks/mlsecevade/PEutils/goodware"
        section_population, what_from_who = CGammaSectionsEvasionProblem.\
                                                create_section_population_from_folder(
                                                    goodware, 
                                                    how_many=10, 
                                                    sections_to_extract=['.rdata']
                                                )
        
        self.attack = CGammaSectionsEvasionProblem(
                    section_population, 
                    self.ember_model, 
                    population_size=kwargs["population_size"], 
                    penalty_regularizer=kwargs["penalty_regularizer"], 
                    iterations=kwargs["iterations"], 
                    threshold=kwargs["threshold"]
                )


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

            print(f"[*] Executing GAMMA attack on sample index {j}...")
            
            engine = CGeneticAlgorithm(self.attack)
            y_pred, adv_score, adv_ds, f_obj = engine.run(byte_array, y)
            adv_Xnd = adv_ds.X[0,:].tondarray()
            
            # writing that to file
            # x_real = adv_Xnd.tolist()[0]
            # x_real_adv = b''.join([bytes([i]) for i in x_real])
		    # with open(path, 'wb') as f:
			#     f.write(x_real_adv)

            adversarial_samples.append(adv_Xnd)

        return adversarial_samples
