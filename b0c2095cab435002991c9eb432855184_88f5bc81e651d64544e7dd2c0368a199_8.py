import torch
import os
import re
import random
from datasets import Dataset
import subprocess
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import LoraConfig, get_peft_model
from trl import GRPOTrainer, GRPOConfig

# 1. 加载模型
model_name = "./gemma-3-4b-it"
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    device_map="auto",
    torch_dtype=torch.bfloat16,
    attn_implementation='eager',
).eval()

tokenizer = AutoTokenizer.from_pretrained(model_name)

# 2. 配置LoRA
peft_config = LoraConfig(
    r=16,
    lora_alpha=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                   "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0,
    bias="none",
    task_type="CAUSAL_LM"
)

model = get_peft_model(model, peft_config)
model.enable_input_require_grads()

# 3. 基础路径配置
BASE_CASEPATH = os.path.normpath(r'C:\Users\Administrator.DESKTOP-A9R1SCS\Desktop\GRPOTEST1\code\data\testcase1')
RULEID = '1234567'
IS_ALERT = 1
NO_ALERT = 0

# 4. 扩展攻击类型配置
ATTACK_TYPE_MAP = {
    "log4j": {
        "positive_pcap": "log4j_parse.log",
        "negative_pcap": "log4j_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "log4j", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "log4j", "vd"),
        }
    },
    "ciscorouterhttp": {
        "positive_pcap": "ciscorouterhttp_parse.log",
        "negative_pcap": "ciscorouterhttp_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "ciscorouterhttp", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "ciscorouterhttp", "vd"),
        }
    },
    "plexdvr": {
        "positive_pcap": "plexdvr_parse.log",
        "negative_pcap": "plexdvr_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "plexdvr", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "plexdvr", "vd"),
        }
    },
    "huelightblackout": {
        "positive_pcap": "huelightblackout_parse.log",
        "negative_pcap": "huelightblackout_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "huelightblackout", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "huelightblackout", "vd"),
        }
    },
    "wannacry": {
        "positive_pcap": "wannacry_parse.log",
        "negative_pcap": "wannacry_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "wannacry", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "wannacry", "vd"),
        }
    },
    "torii": {
        "positive_pcap": "torii_parse.log",
        "negative_pcap": "torii_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "torii", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "torii", "vd"),
        }
    },
    "cryptowall": {
        "positive_pcap": "cryptowall_parse.log",
        "negative_pcap": "cryptowall_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "cryptowall", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "cryptowall", "vd"),
        }
    },
    "eternalblue": {
        "positive_pcap": "eternalblue_parse.log",
        "negative_pcap": "eternalblue_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "eternalblue", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "eternalblue", "vd"),
        }
    },
    "alexa": {
        "positive_pcap": "alexa_parse.log",
        "negative_pcap": "alexa_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "alexa", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "alexa", "vd"),
        }
    },
    "mirai": {
        "positive_pcap": "mirai_parse.log",
        "negative_pcap": "mirai_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "mirai", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "mirai", "vd"),
        }
    },
    "sambacry": {
        "positive_pcap": "sambacry_parse.log",
        "negative_pcap": "sambacry_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "sambacry", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "sambacry", "vd"),
        }
    },
    "modbusfakecmd": {
        "positive_pcap": "modbusfakecmd_parse.log",
        "negative_pcap": "modbusfakecmd_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "modbusfakecmd", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "modbusfakecmd", "vd"),
        }
    },
    "spookyssl": {
        "positive_pcap": "spookyssl_parse.log",
        "negative_pcap": "spookyssl_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "spookyssl", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "spookyssl", "vd"),
        }
    },
    # 4. 扩展攻击类型配置
    "cryptowall": {
        "positive_pcap": "cryptowall_parse.log",
        "negative_pcap": "cryptowall_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "cryptowall", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "cryptowall", "vd"),
        }
    },
    "bladabindi": {
        "positive_pcap": "bladabindi_parse.log",
        "negative_pcap": "bladabindi_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "bladabindi", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "bladabindi", "vd"),
        }
    },
    "ciscoroutercmp": {
        "positive_pcap": "ciscoroutercmp_parse.log",
        "negative_pcap": "ciscoroutercmp_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "ciscoroutercmp", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "ciscoroutercmp", "vd"),
        }
    },
    "conficker": {
        "positive_pcap": "conficker_parse.log",
        "negative_pcap": "conficker_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "conficker", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "conficker", "vd"),
        }
    },
    "gh0strat": {
        "positive_pcap": "gh0strat_parse.log",
        "negative_pcap": "gh0strat_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "gh0strat", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "gh0strat", "vd"),
        }
    },
    "pony": {
        "positive_pcap": "pony_parse.log",
        "negative_pcap": "pony_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "pony", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "pony", "vd"),
        }
    },
    "trojanvalyria": {
        "positive_pcap": "trojanvalyria_parse.log",
        "negative_pcap": "trojanvalyria_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "trojanvalyria", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "trojanvalyria", "vd"),
        }
    },
    "virut": {
        "positive_pcap": "virut_parse.log",
        "negative_pcap": "virut_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "virut", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "virut", "vd"),
        }
    },
    "yakesmalware": {
        "positive_pcap": "yakesmalware_parse.log",
        "negative_pcap": "yakesmalware_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "yakesmalware", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "yakesmalware", "vd"),
        }
    },
    "locky": {
        "positive_pcap": "locky_parse.log",
        "negative_pcap": "locky_vd.txt",
        "paths": {
            "traffic_log": os.path.join(BASE_CASEPATH, "locky", "traffic_log"),
            "vd": os.path.join(BASE_CASEPATH, "locky", "vd"),
        }
    }
}

# 5. 安全文件检查
def safe_file_check(full_path):
    if not os.path.exists(full_path):
        print(f"警告：文件 {full_path} 不存在，将跳过相关检测")
        return False
    return True

# 6. 上下文加载函数
def load_attack_context(attack_type):
    attack_config = ATTACK_TYPE_MAP.get(attack_type)
    if not attack_config:
        return "", ""
    
    # 加载漏洞描述
    vd_string = ""
    neg_path = os.path.join(attack_config["paths"]["vd"], attack_config["negative_pcap"])
    if safe_file_check(neg_path):
        try:
            with open(neg_path, 'r', encoding='utf-8') as f:
                vd_string = f.read().strip()
        except Exception as e:
            print(f"加载漏洞描述失败: {str(e)}")
    
    # 加载流量日志
    log_string = ""
    pos_path = os.path.join(attack_config["paths"]["traffic_log"], attack_config["positive_pcap"])
    if safe_file_check(pos_path):
        try:
            with open(pos_path, 'r', encoding='utf-8') as f:
                log_string = f.read().strip()
        except Exception as e:
            print(f"加载流量日志失败: {str(e)}")
    
    return vd_string, log_string

# 7. 训练提示生成
my_prompts = []
for attack_type in ATTACK_TYPE_MAP.keys():
    vd_str, log_str = load_attack_context(attack_type)
    prompt_text = (
        f"Given the vulnerability description context that: {vd_str}\n"
        f"and given the traffic log context that: {log_str}\n"
        f"Write a Snort rule to detect {attack_type} attacks. Fuzz on the above rule to create 5 simpler rules. Only output the rules."
    )
    print("[DEBUG] Generated prompt:", prompt_text)
    my_prompts.append({"prompt": prompt_text})

# 8. IPS检测函数
def ips(caseid, rule, attack_type, is_positive=True):
    try:
        attack_config = ATTACK_TYPE_MAP.get(attack_type)
        if not attack_config:
            raise ValueError(f"未知攻击类型: {attack_type}")

        file_type = "positive_pcap" if is_positive else "negative_pcap"
        pcap_file = attack_config[file_type]
        traffic_dir = "traffic_log" if is_positive else "vd"
        
        full_path = os.path.join(attack_config["paths"][traffic_dir], pcap_file)
        if not safe_file_check(full_path):
            return NO_ALERT

        def format_docker_path(path):
            return os.path.normpath(path).replace('\\', '/')

        cmd = [
            'docker', 'run', '-it', '--rm', '--net=host',
            '-v', f'{format_docker_path(attack_config["paths"]["traffic_log"])}:/pcap',
            '-v', f'{format_docker_path(attack_config["paths"]["vd"])}:/etc/snort/rules',
            '-v', f'{format_docker_path(os.path.join(BASE_CASEPATH, attack_type, "ips_log"))}:/var/log/snort/',
            'linton/docker-snort', 'snort',
            '-r', f'/pcap/{pcap_file}',
            '-c', '/etc/snort/etc/snort.conf',
            '-k', 'none', '-A', 'console'
        ]

        p = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True)
        out, err = p.communicate()
        
        return IS_ALERT if RULEID in out else NO_ALERT
    except Exception as e:
        print(f"IPS检测异常: {str(e)}")
        return NO_ALERT

# 9. 奖励函数
def reward_func_snort(prompts, completions, **kwargs):
    rewards = []
    for prompt, completion in zip(prompts, completions):
        try:
            if isinstance(prompt, str):
                prompt = {"prompt": prompt}
                
            prompt_text = prompt.get("prompt", "").lower()
            attack_type = next(
                (key for key in ATTACK_TYPE_MAP if key in prompt_text),
                None
            )
            if not attack_type:
                rewards.append(-5.0)
                continue

            rules = re.findall(
                r'^alert\s+.+?\);?$',
                completion,
                re.MULTILINE | re.DOTALL
            )
            
            if len(rules) < 5:
                rewards.append(-3.0)
                continue
                
            scored_rules = []
            for rule in rules[:5]:                
                result_pos = ips('', rule, attack_type, is_positive=True)
                result_neg = ips('', rule, attack_type, is_positive=False)
                
                content_bonus = 3.0 if 'jndi:ldap://' in rule.lower() else 0.0
                base_score = 2.0 * result_pos + 1.5 * (1 - result_neg)
                simplicity_bonus = max(0, 1.0 - 0.1 * len(rule.split()))
                
                total_score = base_score + content_bonus + simplicity_bonus
                scored_rules.append(total_score)
            
            if not scored_rules:
                rewards.append(-2.0)
            else:
                rewards.append(float(max(scored_rules)))
                
        except Exception as e:
            print(f"奖励计算失败: {str(e)}")
            rewards.append(-1.0)
    return rewards

# 10. 模糊测试函数
def fuzz_rule(original_rule, attack_type):
    fuzzed_rules = [original_rule]
    
    order_preserved_fields = {
        "log4j": ["content"],
        "ciscorouterhttp": ["content"],
        "plexdvr": ["content"],
        "huelightblackout": ["content"],
        "wannacry": ["content"],
        "torii": ["content"],
        "cryptowall": ["POST", "php", "Host"],
        "eternalblue": ["SMB", "|A0|", "byte_test"],
        "alexa": ["content", "offset", "depth"],
        "mirai": ["content", "threshold"],
        "sambacry": ["FE 53 4D 42", "03 00", "sid"],
        "modbusfakecmd": ["modbus_func"],
        "spookyssl": ["2b 06 01 05 05 07 08 09", "06 03 55 1d 1e"],
    }
    
    for _ in range(4):
        parts = [p.strip() for p in original_rule.split(';') if p.strip()]
        
        if attack_type in order_preserved_fields:
            ordered_parts = []
            remaining_parts = parts.copy()
            for key in order_preserved_fields[attack_type]:
                for part in remaining_parts:
                    if key in part:
                        ordered_parts.append(part)
                        remaining_parts.remove(part)
                        break
            parts = ordered_parts + remaining_parts
        
        non_key_parts = [p for p in parts if not any(
            k in p for k in order_preserved_fields.get(attack_type, [])
        )]
        random.shuffle(non_key_parts)
        
        key_parts = [p for p in parts if any(
            k in p for k in order_preserved_fields.get(attack_type, [])
        )]
        fuzzed_rule = '; '.join(key_parts + non_key_parts).strip()
        if not fuzzed_rule.endswith(';'):
            fuzzed_rule += ';'
        fuzzed_rules.append(fuzzed_rule)
    
    return fuzzed_rules[:5]

# 11. 创建训练数据集
train_dataset = Dataset.from_list(my_prompts * 3)

# 12. 训练配置
training_args = GRPOConfig(
    output_dir="snort_rule_grpo",
    learning_rate=1e-5,
    logging_steps=1,
    gradient_accumulation_steps=8,
    per_device_train_batch_size=8,
    max_completion_length=128,
    max_steps=5,
)

# 13. 创建训练器
trainer = GRPOTrainer(
    model=model,
    reward_funcs=reward_func_snort,
    args=training_args,
    train_dataset=train_dataset,
    peft_config=None,
)

# 14. 执行训练
trainer.train()

# 15. 保存模型
model.save_pretrained("snort_rule_lora")
tokenizer.save_pretrained("snort_rule_lora")

# 16. 测试提示生成
test_inputs = []
for attack_type in ATTACK_TYPE_MAP.keys():
    vd_str, log_str = load_attack_context(attack_type)
    prompt_text = (
        f"Given the vulnerability description context that: {vd_str}\n"
        f"and given the traffic log context that: {log_str}\n"
        f"Write a Snort rule to detect {attack_type} attacks. Only output the rule."
    )
    test_inputs.append(prompt_text)

# 17. 测试代码
print("\n测试不同攻击类型的规则生成：")
for test_inp in test_inputs:
    inputs = tokenizer(
        test_inp,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=2048,
    ).to(model.device)
    
    outputs = model.generate(
        **inputs,
        max_new_tokens=100,
        temperature=0.7,
        do_sample=True
    )
    print(f"\nPrompt: {test_inp[:500]}...")
    print("生成的Snort规则：")
    print(tokenizer.decode(outputs[0], skip_special_tokens=True))