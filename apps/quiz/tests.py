from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.sessions.models import Session
from .models import QuizCategory, Question, Answer, QuizSession, QuizAttempt
import json


class QuizViewsTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        
        # Create test data
        self.category = QuizCategory.objects.create(
            name="Test Category",
            category_type="school",
            is_active=True
        )
        
        self.question = Question.objects.create(
            question_text="Test Question?",
            question_type="classic",
            category=self.category,
            points=10,
            explanation="Test explanation"
        )
        
        self.correct_answer = Answer.objects.create(
            question=self.question,
            answer_text="Correct Answer",
            is_correct=True
        )
        
        self.wrong_answer = Answer.objects.create(
            question=self.question,
            answer_text="Wrong Answer",
            is_correct=False
        )

    def test_quiz_home_view(self):
        """Test that quiz home page loads correctly."""
        response = self.client.get(reverse('quiz:home'))
        self.assertEqual(response.status_code, 200)
        # Check that the page contains quiz content (check for specific form elements)
        self.assertContains(response, 'name="category"')
        self.assertContains(response, 'name="question_type"')

    def test_start_quiz_get(self):
        """Test GET request to start quiz page."""
        response = self.client.get(reverse('quiz:start_quiz'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.category.name)

    def test_start_quiz_post_valid(self):
        """Test POST request to start quiz with valid data."""
        response = self.client.post(reverse('quiz:start_quiz'), {
            'category': self.category.id,
            'question_type': 'classic'
        })
        self.assertEqual(response.status_code, 302)  # Redirect to quiz question
        
        # Check that session was created
        self.assertTrue(QuizSession.objects.filter(category=self.category).exists())

    def test_start_quiz_post_invalid(self):
        """Test POST request to start quiz with invalid data."""
        response = self.client.post(reverse('quiz:start_quiz'), {
            'category': '',
            'question_type': 'classic'
        })
        self.assertEqual(response.status_code, 302)  # Redirect back to start

    def test_session_validation(self):
        """Test session access validation."""
        # Create a quiz session
        session = QuizSession.objects.create(
            session_key="test-key",
            category=self.category,
            question_type="classic"
        )
        
        # Try to access without proper session
        response = self.client.get(reverse('quiz:quiz_question', args=[session.id]))
        self.assertEqual(response.status_code, 404)  # Should be denied

    def test_submit_answer_creates_attempt(self):
        """Test that submitting answer creates QuizAttempt record."""
        # Create session and set in client session
        session = QuizSession.objects.create(
            session_key="test-key",
            category=self.category,
            question_type="classic"
        )
        
        # Set session in client
        client_session = self.client.session
        client_session['quiz_session_id'] = session.id
        client_session.save()
        
        # Submit answer
        response = self.client.post(
            reverse('quiz:submit_answer', args=[session.id]),
            {'answer_id': self.correct_answer.id}
        )
        
        self.assertEqual(response.status_code, 200)
        
        # Check that attempt was created
        self.assertTrue(QuizAttempt.objects.filter(
            session=session,
            question=self.question,
            answer=self.correct_answer
        ).exists())

    def test_character_result_calculation(self):
        """Test character result calculation function."""
        from .views import calculate_character_result
        
        # Test different percentage ranges
        character, message = calculate_character_result(95)
        self.assertEqual(character, "ara")
        self.assertIn("անտուն կիբեռգիտակ", message)
        
        character, message = calculate_character_result(75)
        self.assertEqual(character, "ara")
        
        character, message = calculate_character_result(55)
        self.assertEqual(character, "shamiram")
        
        character, message = calculate_character_result(25)
        self.assertEqual(character, "shamiram")