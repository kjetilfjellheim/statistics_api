use chrono::Utc;

use crate::model::{apperror::ApplicationError, models::{StatisticsDetailType, StatisticsListType}};

pub struct StatisticsDao {
    
}

impl StatisticsDao {
    pub fn new() -> Self {
        StatisticsDao {  }
    }

    pub async fn get_statistics_list(&self) -> Result<StatisticsListType, ApplicationError> {
        Ok(StatisticsListType::new(vec![
            StatisticsDetailType::new(
                1,
                101,
                "Municipality A".to_string(),
                1001,
                "Population".to_string(),
                10000.0,
                2020,
                Utc::now(),
                Utc::now(),
                "user1".to_string(),
                "user1".to_string(),
            ),
            StatisticsDetailType::new(
                2,
                102,
                "Municipality B".to_string(),
                1002,
                "Area".to_string(),
                500.0,
                2020,
                Utc::now(),
                Utc::now(),
                "user2".to_string(),
                "user2".to_string(),
            ),
        ]))
    }
}