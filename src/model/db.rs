use chrono::{DateTime, Utc};

struct Data {
    pub id: u64,
    pub municipality_id: u64,
    pub statistic_id: u64,
    pub value: f64,
    pub year: u16,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_by: String,
    pub created_by: String,
}

impl Data {
    pub fn new(id: u64, municipality_id: u64, statistic_id: u64, value: f64, year: u16, updated_by: String, created_by: String) -> Self {
        let now = Utc::now();
        Data { id, municipality_id, statistic_id, value, year, updated_at: now, created_at: now, updated_by, created_by }
    }
}

struct Municipality {
    pub id: u64,
    pub name: String,
}

impl Municipality {
    pub fn new(id: u64, name: String) -> Self {
        Municipality { id, name }
    }
}

struct Statistic {
    pub id: u64,
    pub name: String,
}

impl Statistic {
    pub fn new(id: u64, name: String) -> Self {
        Statistic { id, name }
    }
}
