"""
train_ppo.py
============
Training script for the Stable-Baselines3 PPO SDN Mitigation Agent.
Trains on SDNIntrusionEnv with domain randomization and saves checkpoint.
"""

import os
import argparse
import logging
import numpy as np

from src.rl.sdn_env import SDNIntrusionEnv

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def train_ppo_agent(
    total_timesteps: int = 100000,
    save_path: str = "models/rl_ppo_agent.zip",
    learning_rate: float = 3e-4,
    n_steps: int = 2048,
    batch_size: int = 64,
    n_epochs: int = 10,
    gamma: float = 0.99,
    gae_lambda: float = 0.95,
    clip_range: float = 0.2,
    ent_coef: float = 0.01,
):
    """
    Train PPO reinforcement learning policy using Stable-Baselines3.
    """
    logger.info("=" * 70)
    logger.info("STARTING PPO REINFORCEMENT LEARNING POLICY TRAINING")
    logger.info("=" * 70)
    logger.info("Target Timesteps: %d | Output Model: %s", total_timesteps, save_path)

    os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)

    try:
        from stable_baselines3 import PPO
        from stable_baselines3.common.env_util import make_vec_env

        # Create vectorized environment
        env = make_vec_env(lambda: SDNIntrusionEnv(max_steps=1000), n_envs=4)

        model = PPO(
            "MlpPolicy",
            env,
            learning_rate=learning_rate,
            n_steps=n_steps,
            batch_size=batch_size,
            n_epochs=n_epochs,
            gamma=gamma,
            gae_lambda=gae_lambda,
            clip_range=clip_range,
            ent_coef=ent_coef,
            verbose=1,
        )

        logger.info("Training PPO agent across %d timesteps...", total_timesteps)
        model.learn(total_timesteps=total_timesteps)
        model.save(save_path)
        logger.info("PPO Agent successfully trained and persisted to %s", save_path)
        return model

    except ImportError:
        logger.warning("stable_baselines3 not installed in local environment. Creating serialized policy placeholder.")
        # Create dummy file indicating policy config
        with open(save_path.replace(".zip", ".info"), "w") as f:
            f.write(f"PPO Agent Configuration: timesteps={total_timesteps}, lr={learning_rate}\n")
        logger.info("Saved policy configuration info to %s", save_path.replace(".zip", ".info"))
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PPO SDN Intrusion Mitigation Agent")
    parser.add_argument("--total_timesteps", type=int, default=50000, help="Total training steps")
    parser.add_argument("--save_path", type=str, default="models/rl_ppo_agent.zip", help="Output model path")
    parser.add_argument("--lr", type=float, default=3e-4, help="Learning rate")
    args = parser.parse_args()

    train_ppo_agent(
        total_timesteps=args.total_timesteps,
        save_path=args.save_path,
        learning_rate=args.lr,
    )
