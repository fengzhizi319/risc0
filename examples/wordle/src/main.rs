// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod wordlist;

use std::io;

use risc0_zkvm::{
    serde::{from_slice, to_vec},
    sha::Digest,
    Prover, Receipt,
};
use wordle_core::{GameState, WordFeedback, WORD_LENGTH};
use wordle_methods::{WORDLE_ELF, WORDLE_ID};

// The "server" is an agent in the Wordle game that checks the player's guesses.
struct Server<'a> {
    // The server chooses the secret word, and remembers it until the end of the game. It is
    // private because the player shouldn't know the word until the game is over.
    secret_word: &'a str,
}

impl<'a> Server<'a> {
    pub fn new(secret_word: &'a str) -> Self {
        Self { secret_word }
    }

    pub fn get_secret_word_hash(&self) -> Digest {
        let receipt = self.check_round("_____");
        let game_state: GameState = from_slice(&receipt.journal).unwrap();
        game_state.correct_word_hash
    }

    pub fn check_round(&self, guess_word: &str) -> Receipt {
        let mut prover = Prover::new(WORDLE_ELF).expect("failed to construct prover");

        prover.add_input_u32_slice(to_vec(self.secret_word).unwrap().as_slice());
        prover.add_input_u32_slice(to_vec(&guess_word).unwrap().as_slice());

        prover.run().unwrap()
    }
}

// The "player" is an agent in the Wordle game that tries to guess the server's
// secret word.
struct Player {
    // The player remembers the hash of the secret word that the server commits to at the beginning
    // of the game. By comparing the hash after each guess, the player knows if the server cheated
    // by changing the word.
    pub hash: Digest,
}

impl Player {
    pub fn check_receipt(&self, receipt: Receipt) -> WordFeedback {
        receipt
            .verify(&WORDLE_ID)
            .expect("receipt verification failed");

        let game_state: GameState = from_slice(&receipt.journal).unwrap();
        if game_state.correct_word_hash != self.hash {
            panic!("The hash mismatched, so the server cheated!");
        }
        game_state.feedback
    }
}

fn read_stdin_guess() -> String {
    let mut guess = String::new();
    loop {
        io::stdin().read_line(&mut guess).unwrap();
        guess.pop(); // remove trailing newline

        if guess.chars().count() == WORD_LENGTH {
            break;
        } else {
            println!("Your guess must have 5 letters. Try again :)");
            guess.clear();
        }
    }
    guess
}

fn play_rounds(server: Server, player: Player, rounds: usize) -> bool {
    for turn_index in 0..rounds {
        let remaining_guesses = rounds - turn_index;
        let guess_word = read_stdin_guess();
        let receipt = server.check_round(guess_word.as_str());
        let score = player.check_receipt(receipt);

        if remaining_guesses == rounds {
            println!("Good guess! Our server has calculated your results.");
            println!("You'll have 6 chances to get the word right.");
        } else {
            println!("You have {} guesses remaining.", remaining_guesses);
        }

        score.print(guess_word.as_str());
        if score.game_is_won() {
            return true;
        }
    }
    false
}

fn main() {
    println!("Welcome to fair Wordle! Enter a five-letter word.");

    let server = Server::new(wordlist::pick_word());
    let player = Player {
        hash: server.get_secret_word_hash(),
    };

    if play_rounds(server, player, 6) {
        println!("You won!\n");
    } else {
        println!("Game over!\n");
    }
}

#[cfg(test)]
mod tests {
    use wordle_core::{LetterFeedback, WordFeedback};

    use crate::{Player, Server};

    const TEST_GUESS_WRONG: &str = "roofs";
    const TEST_GUESS_RIGHT: &str = "proof";

    #[test]
    fn main() {
        let server = Server::new("proof");
        let player = Player {
            hash: server.get_secret_word_hash(),
        };

        let guess_word = TEST_GUESS_WRONG;
        let receipt = server.check_round(&guess_word);
        let score = player.check_receipt(receipt);
        assert!(
            !score.game_is_won(),
            "Incorrect guess should not win the game"
        );
        let guess_word = TEST_GUESS_RIGHT;
        let receipt = server.check_round(&guess_word);
        let score = player.check_receipt(receipt);
        assert!(score.game_is_won(), "Correct guess should win the game");
    }

    /// If a guessed letter is present in every position where it ought to
    /// appear, and also in an incorrect position, the 'bonus' letter
    /// shouldn't flag yellow
    #[test]
    fn test_partial_match_false_positives() {
        let server = Server::new("spare");
        let player = Player {
            hash: server.get_secret_word_hash(),
        };

        let guess_word = "apple";
        let receipt = server.check_round(&guess_word);
        let score = player.check_receipt(receipt);
        score.print(guess_word);

        assert!(
            score.0[0] == LetterFeedback::Present,
            "Other partials should be yellow"
        );

        assert!(
            score.0[1] == LetterFeedback::Correct,
            "Consumed exact matches should be green"
        );

        assert!(
            score.0[2] == LetterFeedback::Miss,
            "Excessive instances of letter should not flag yellow"
        );

        assert!(
            score.0[1] == LetterFeedback::Correct,
            "Misses should still miss"
        );

        assert!(
            score.0[1] == LetterFeedback::Correct,
            "Unconsumed matches should be green"
        );
    }
}