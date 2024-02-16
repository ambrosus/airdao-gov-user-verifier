use chrono::Utc;
use rand::{rngs::ThreadRng, seq::SliceRandom, thread_rng};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};

use crate::users_manager::QuizResult;

#[derive(Clone, Debug)]
pub struct Quiz {
    pub config: QuizConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuizConfig {
    pub secret: String,
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    pub time_to_solve: Duration,
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    pub failed_quiz_block_duration: Duration,
    pub number_of_quiz_questions_shown: HashMap<QuizQuestionDifficultyLevel, u64>,
    pub minimum_valid_answers_required: HashMap<QuizQuestionDifficultyLevel, u64>,
    pub questions: Vec<QuizQuestion>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuizQuestion {
    pub title: String,
    #[serde(skip_serializing)]
    pub difficulty: QuizQuestionDifficultyLevel,
    pub variants: Vec<QuizVariant>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum QuizQuestionDifficultyLevel {
    Easy,
    Moderate,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuizVariant {
    pub text: String,
    #[serde(skip_serializing)]
    pub is_correct: bool,
}

#[derive(Debug, Deserialize)]
pub struct QuizAnswer {
    pub question: String,
    pub variant: String,
}

impl Quiz {
    /// Returns randomly shuffled questions to be shown
    pub fn get_random_quiz_questions(&self) -> Vec<QuizQuestion> {
        let number_of_shown_easy_questions = self
            .config
            .number_of_quiz_questions_shown
            .get(&QuizQuestionDifficultyLevel::Easy)
            .cloned()
            .unwrap_or_default() as usize;
        let number_of_shown_moderate_questions = self
            .config
            .number_of_quiz_questions_shown
            .get(&QuizQuestionDifficultyLevel::Moderate)
            .cloned()
            .unwrap_or_default() as usize;

        let mut rng = thread_rng();
        let easy_questions = self.get_random_quiz_questions_by_difficulty(
            &mut rng,
            QuizQuestionDifficultyLevel::Easy,
            number_of_shown_easy_questions,
        );
        let moderate_questions = self.get_random_quiz_questions_by_difficulty(
            &mut rng,
            QuizQuestionDifficultyLevel::Moderate,
            number_of_shown_moderate_questions,
        );

        // Concat all difficulty levels into single list and return
        let mut questions = Vec::with_capacity(easy_questions.len() + moderate_questions.len());
        questions.extend(easy_questions.into_iter().cloned());
        questions.extend(moderate_questions.into_iter().cloned());
        questions
    }

    fn get_random_quiz_questions_by_difficulty(
        &self,
        mut rng: &mut ThreadRng,
        difficulty: QuizQuestionDifficultyLevel,
        count: usize,
    ) -> Vec<&QuizQuestion> {
        if count == 0 {
            return vec![];
        }

        // Filter questions by difficulty level
        let mut questions = self
            .config
            .questions
            .iter()
            .filter(|question| question.difficulty == difficulty)
            .collect::<Vec<_>>();
        // Randomly shuffle questions
        questions.as_mut_slice().shuffle(&mut rng);

        // Remove questions from the end until reaches the required count left
        loop {
            if questions.len() <= count {
                break;
            }

            if questions.pop().is_none() {
                break;
            }
        }

        questions
    }

    /// Verifies provided quiz answers
    pub fn verify_answers(&self, answers: Vec<QuizAnswer>) -> QuizResult {
        let mut easy_valid_answers = 0;
        let mut moderate_valid_answers = 0;

        for answer in answers {
            match self
                .config
                .questions
                .iter()
                .find(|question| {
                    // Filter by question title
                    if question.title != answer.question {
                        return false;
                    }

                    // Find a variant in question and verify it's a correct one
                    question
                        .variants
                        .iter()
                        .any(|variant| variant.text == answer.variant && variant.is_correct)
                })
                .map(|question| &question.difficulty)
            {
                Some(QuizQuestionDifficultyLevel::Easy) => {
                    easy_valid_answers += 1;
                }
                Some(QuizQuestionDifficultyLevel::Moderate) => {
                    moderate_valid_answers += 1;
                }
                None => {}
            }
        }

        if easy_valid_answers
            >= self
                .config
                .minimum_valid_answers_required
                .get(&QuizQuestionDifficultyLevel::Easy)
                .cloned()
                .unwrap_or_default()
            && moderate_valid_answers
                >= self
                    .config
                    .minimum_valid_answers_required
                    .get(&QuizQuestionDifficultyLevel::Moderate)
                    .cloned()
                    .unwrap_or_default()
        {
            QuizResult::Solved
        } else {
            QuizResult::Failed(Utc::now() + self.config.failed_quiz_block_duration)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_de_quiz_config() {
        let config = r#"
        {
            "secret": "TestSecret",
            "timeToSolve": 300,
            "failedQuizBlockDuration": 172800,
            "numberOfQuizQuestionsShown": {
                "easy": 2,
                "moderate": 1
            },
            "minimumValidAnswersRequired": {
                "easy": 1,
                "moderate": 1
            },
            "questions": [
                {
                    "title": "Question 1",
                    "difficulty": "easy",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                },
                {
                    "title": "Question 2",
                    "difficulty": "moderate",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some invalid answer 3", false],
                        ["some valid answer 4", true]
                    ]
                },
                {
                    "title": "Question 3",
                    "difficulty": "easy",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                },
                {
                    "title": "Question 4",
                    "difficulty": "easy",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                }
            ]
        }
        "#;

        serde_json::from_str::<QuizConfig>(config).unwrap();
    }

    #[test]
    fn test_quiz_answers() {
        let config = r#"
        {
            "secret": "TestSecret",
            "timeToSolve": 300,
            "failedQuizBlockDuration": 172800,
            "numberOfQuizQuestionsShown": {
                "easy": 2,
                "moderate": 1
            },
            "minimumValidAnswersRequired": {
                "easy": 1,
                "moderate": 1
            },
            "questions": [
                {
                    "title": "Question 1",
                    "difficulty": "easy",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                },
                {
                    "title": "Question 2",
                    "difficulty": "moderate",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some invalid answer 3", false],
                        ["some valid answer 4", true]
                    ]
                },
                {
                    "title": "Question 3",
                    "difficulty": "easy",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                },
                {
                    "title": "Question 4",
                    "difficulty": "easy",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                }
            ]
        }
        "#;

        let config = serde_json::from_str::<QuizConfig>(config).unwrap();
        let quiz = Quiz { config };

        struct TestCase {
            title: &'static str,
            input: &'static str,
            expected: bool,
        }

        let test_cases = [
            TestCase {
                title: "All answers are valid",
                input: r#"
                    [
                        ["Question 1", "some valid answer 3"],
                        ["Question 2", "some valid answer 4"],
                        ["Question 3", "some valid answer 3"],
                        ["Question 4", "some valid answer 3"]
                    ]
                "#,
                expected: true,
            },
            TestCase {
                title: "Minimum required answers are valid",
                input: r#"
                    [
                        ["Question 1", "some invalid answer 2"],
                        ["Question 2", "some valid answer 4"],
                        ["Question 3", "some valid answer 3"]
                    ]
                "#,
                expected: true,
            },
            TestCase {
                title: "Not enough easy level valid answers",
                input: r#"
                    [
                        ["Question 1", "some invalid answer 1"],
                        ["Question 2", "some valid answer 4"]
                    ]
                "#,
                expected: false,
            },
            TestCase {
                title: "Not enough moderate level valid answers",
                input: r#"
                    [
                        ["Question 1", "some valid answer 3"],
                        ["Question 2", "some invalid answer 3"]
                    ]
                "#,
                expected: false,
            },
        ];

        for (
            i,
            TestCase {
                title,
                input,
                expected,
            },
        ) in test_cases.into_iter().enumerate()
        {
            match serde_json::from_str::<Vec<QuizAnswer>>(input) {
                Ok(answers) => assert_eq!(
                    quiz.verify_answers(answers) == QuizResult::Solved,
                    expected,
                    "Test case #{i} '{title}' failed!"
                ),
                Err(e) => panic!("Test case #{i} '{title}': deserialization failure. Error: {e:?}"),
            }
        }
    }

    #[test]
    fn test_quiz_to_be_shown() {
        let config = r#"
        {
            "secret": "TestSecret",
            "timeToSolve": 300,
            "failedQuizBlockDuration": 172800,
            "numberOfQuizQuestionsShown": {
                "easy": 2,
                "moderate": 1
            },
            "minimumValidAnswersRequired": {
                "easy": 1,
                "moderate": 1
            },
            "questions": [
                {
                    "title": "Question 1",
                    "difficulty": "easy",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                },
                {
                    "title": "Question 2",
                    "difficulty": "moderate",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some invalid answer 3", false],
                        ["some valid answer 4", true]
                    ]
                },
                {
                    "title": "Question 3",
                    "difficulty": "easy",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                },
                {
                    "title": "Question 4",
                    "difficulty": "easy",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                }
            ]
        }
        "#;

        let config = serde_json::from_str::<QuizConfig>(config).unwrap();
        let quiz = Quiz { config };

        let questions = quiz.get_random_quiz_questions();
        assert_eq!(questions.len(), 3);
        assert_eq!(
            questions
                .iter()
                .filter(|question| question.difficulty == QuizQuestionDifficultyLevel::Easy)
                .count(),
            2
        );
        assert_eq!(
            questions
                .iter()
                .filter(|question| question.difficulty == QuizQuestionDifficultyLevel::Moderate)
                .count(),
            1
        );
    }
}
