use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::users_manager::QuizResult;

#[derive(Clone, Debug)]
pub struct Quiz {
    pub config: QuizConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuizConfig {
    #[serde(deserialize_with = "shared::utils::de_secs_duration")]
    pub failed_quiz_block_duration: Duration,
    pub minimum_valid_answers_required: u64,
    pub questions: Vec<QuizQuestion>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuizQuestion {
    title: String,
    variants: Vec<QuizVariant>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuizVariant {
    text: String,
    #[serde(skip_serializing)]
    is_correct: bool,
}

#[derive(Debug, Deserialize)]
pub struct QuizAnswer {
    question: String,
    variant: String,
}

impl Quiz {
    /// Verifies provided quiz answers
    pub fn verify_answers(&self, answers: Vec<QuizAnswer>) -> QuizResult {
        let valid_answers = answers.into_iter().fold(0u64, |valid_answers, answer| {
            let is_correct_answer = self.config.questions.iter().any(|question| {
                // Filter by question title
                if question.title != answer.question {
                    return false;
                }

                // Find a variant in question and verify it's a correct one
                question
                    .variants
                    .iter()
                    .any(|variant| variant.text == answer.variant && variant.is_correct)
            });

            if is_correct_answer {
                valid_answers + 1
            } else {
                valid_answers
            }
        });

        if valid_answers >= self.config.minimum_valid_answers_required {
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
            "failedQuizBlockDuration": 172800,
            "minimumValidAnswersRequired": 1,
            "questions": [
                {
                    "title": "Question 1",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                },
                {
                    "title": "Question 2",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some invalid answer 3", false],
                        ["some valid answer 4", true]
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
            "failedQuizBlockDuration": 172800,
            "minimumValidAnswersRequired": 1,
            "questions": [
                {
                    "title": "Question 1",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some valid answer 3", true],
                        ["some invalid answer 4", false]
                    ]
                },
                {
                    "title": "Question 2",
                    "variants": [
                        ["some invalid answer 1", false],
                        ["some invalid answer 2", false],
                        ["some invalid answer 3", false],
                        ["some valid answer 4", true]
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
                        ["Question 2", "some valid answer 4"]
                    ]
                "#,
                expected: true,
            },
            TestCase {
                title: "Minimum required answers are valid",
                input: r#"
                    [
                        ["Question 1", "some invalid answer 2"],
                        ["Question 2", "some valid answer 4"]
                    ]
                "#,
                expected: true,
            },
            TestCase {
                title: "Not enough valid answers",
                input: r#"
                    [
                        ["Question 1", "some invalid answer 2"],
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
                    "Test case #{i} failed!"
                ),
                Err(e) => panic!("Test case #{i} '{title}': deserialization failure. Error: {e:?}"),
            }
        }
    }
}
