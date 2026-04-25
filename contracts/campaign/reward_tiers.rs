#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, Env, Address, String, Vec,
};

#[derive(Clone)]
#[contracttype]
pub struct RewardTier {
    pub id: u32,
    pub title: String,
    pub description: String,
    pub amount: i128,
    pub max_backers: u32, // 0 = unlimited
    pub claimed: u32,
}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    CampaignCreator(u64),
    RewardTiers(u64),
}

#[contract]
pub struct CampaignContract;

#[contractimpl]
impl CampaignContract {

    // 🔹 Set Campaign Creator (setup)
    pub fn set_campaign_creator(
        env: Env,
        campaign_id: u64,
        creator: Address,
    ) {
        creator.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::CampaignCreator(campaign_id), &creator);
    }

    // 🔹 Add Reward Tier
    pub fn add_reward_tier(
        env: Env,
        campaign_id: u64,
        creator: Address,
        tier: RewardTier,
    ) {
        creator.require_auth();

        let stored_creator: Address = env
            .storage()
            .instance()
            .get(&DataKey::CampaignCreator(campaign_id))
            .expect("Campaign not found");

        if stored_creator != creator {
            panic!("Not campaign owner");
        }

        let mut tiers: Vec<RewardTier> = env
            .storage()
            .instance()
            .get(&DataKey::RewardTiers(campaign_id))
            .unwrap_or(Vec::new(&env));

        tiers.push_back(tier);

        env.storage()
            .instance()
            .set(&DataKey::RewardTiers(campaign_id), &tiers);

        env.events().publish(
            ("reward_tier_added", campaign_id),
            "tier_added",
        );
    }

    // 🔹 Get Reward Tiers
    pub fn get_reward_tiers(
        env: Env,
        campaign_id: u64,
    ) -> Vec<RewardTier> {
        env.storage()
            .instance()
            .get(&DataKey::RewardTiers(campaign_id))
            .unwrap_or(Vec::new(&env))
    }

    // 🔹 Claim Reward Tier
    pub fn claim_reward_tier(
        env: Env,
        campaign_id: u64,
        tier_id: u32,
        backer: Address,
    ) {
        backer.require_auth();

        let mut tiers: Vec<RewardTier> = env
            .storage()
            .instance()
            .get(&DataKey::RewardTiers(campaign_id))
            .expect("No reward tiers");

        let mut found = false;

        for i in 0..tiers.len() {
            let mut tier = tiers.get(i).unwrap();

            if tier.id == tier_id {
                if tier.max_backers != 0 && tier.claimed >= tier.max_backers {
                    panic!("Tier sold out");
                }

                tier.claimed += 1;
                tiers.set(i, tier);
                found = true;
                break;
            }
        }

        if !found {
            panic!("Tier not found");
        }

        env.storage()
            .instance()
            .set(&DataKey::RewardTiers(campaign_id), &tiers);

        env.events().publish(
            ("reward_claimed", campaign_id),
            tier_id,
        );
    }
}