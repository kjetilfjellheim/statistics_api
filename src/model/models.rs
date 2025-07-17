use chrono::{DateTime, Utc};

pub struct StatisticsListType {
    pub statistics: Vec<StatisticsDetailType>,
}

impl StatisticsListType {
    pub fn new(statistics: Vec<StatisticsDetailType>) -> Self {
        StatisticsListType { statistics }
    }
}

pub struct StatisticsDetailType {
    pub id: u64,
    pub municipality_id: u64,
    pub municipality_name: String,
    pub statistic_id: u64,
    pub statistic_name: String,
    pub value: f64,
    pub year: u16,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_by: String,
    pub created_by: String,
}

impl StatisticsDetailType {
    pub fn new(
        id: u64,
        municipality_id: u64,
        municipality_name: String,
        statistic_id: u64,
        statistic_name: String,
        value: f64,
        year: u16,
        updated_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        updated_by: String,
        created_by: String,
    ) -> Self {
        StatisticsDetailType {
            id,
            municipality_id,
            municipality_name,
            statistic_id,
            statistic_name,
            value,
            year,
            updated_at,
            created_at,
            updated_by,
            created_by,
        }
    }
}
