use crate::{dao::statistics::StatisticsDao, model::{apperror::ApplicationError, models::StatisticsListType}};

pub struct StatisticsService {
    statistics_dao: StatisticsDao,
}
impl StatisticsService {
    
    pub fn new(statistics_dao: StatisticsDao) -> Self {
        StatisticsService { statistics_dao }
    }

    pub async fn get_statistics_list(&self) -> Result<StatisticsListType, ApplicationError> {
        self.statistics_dao.get_statistics_list().await
    }
}