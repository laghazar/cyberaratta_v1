#!/usr/bin/env python
"""
Quiz Flow Testing Script
This script tests the complete quiz functionality end-to-end
"""

import os
import sys
import django
from django.test import TestCase, Client
from django.urls import reverse
import json

# Setup Django environment
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberaratta.settings')
django.setup()

from apps.quiz.models import QuizCategory, Question, Answer, QuizSession, QuizResult

def test_quiz_flow():
    """Test complete quiz flow"""
    print("=== QUIZ FLOW TESTING ===")
    
    # Create Django test client
    client = Client()
    
    print("\n1. Testing Quiz Home Page...")
    response = client.get('/quiz/')
    print(f"   Status: {response.status_code}")
    print(f"   Categories in context: {len(response.context.get('categories', []))}")
    
    # Check if categories exist
    categories = QuizCategory.objects.filter(is_active=True)
    print(f"   Database categories: {categories.count()}")
    for cat in categories:
        classic_count = Question.objects.filter(category=cat, question_type='classic', is_active=True).count()
        millionaire_count = Question.objects.filter(category=cat, question_type='millionaire', is_active=True).count()
        print(f"   - {cat.name}: {classic_count} classic, {millionaire_count} millionaire")
    
    print("\n2. Testing Quiz Start...")
    # Test with category that has questions
    test_category = categories.filter(
        question__question_type='classic', 
        question__is_active=True
    ).first()
    
    if test_category:
        print(f"   Using category: {test_category.name}")
        start_data = {
            'category': test_category.id,
            'question_type': 'classic'
        }
        response = client.post('/quiz/start/', start_data)
        print(f"   Start response status: {response.status_code}")
        
        if response.status_code == 302:  # Redirect to question
            print("   ✓ Successfully started quiz")
            
            # Extract session ID from redirect URL
            redirect_url = response.url
            session_id = redirect_url.split('/')[-2]
            print(f"   Session ID: {session_id}")
            
            print("\n3. Testing Question Display...")
            response = client.get(f'/quiz/question/{session_id}/')
            print(f"   Question page status: {response.status_code}")
            
            if response.status_code == 200:
                context = response.context
                question = context.get('question')
                answers = context.get('answers')
                print(f"   Question: {question.question_text[:50]}...")
                print(f"   Answers count: {len(answers) if answers else 0}")
                
                print("\n4. Testing Answer Submission...")
                if answers:
                    # Submit correct answer
                    correct_answer = None
                    for answer in answers:
                        if answer.is_correct:
                            correct_answer = answer
                            break
                    
                    if correct_answer:
                        print(f"   Submitting correct answer: {correct_answer.answer_text}")
                        submit_data = {'answer_id': correct_answer.id}
                        response = client.post(
                            f'/quiz/submit_answer/{session_id}/',
                            json.dumps(submit_data),
                            content_type='application/json'
                        )
                        print(f"   Submit response status: {response.status_code}")
                        
                        if response.status_code == 200:
                            result = response.json()
                            print(f"   Answer correct: {result.get('correct')}")
                            print(f"   Points earned: {result.get('points_earned')}")
                            print("   ✓ Answer submission working")
                        
                        print("\n5. Testing Quiz Session State...")
                        session = QuizSession.objects.get(id=session_id)
                        print(f"   Current question: {session.current_question}")
                        print(f"   Score: {session.score}")
                        print(f"   Completed: {session.is_completed}")
                        
                        # Complete remaining questions
                        total_questions = Question.objects.filter(
                            category=test_category, 
                            question_type='classic', 
                            is_active=True
                        ).count()
                        
                        print(f"\n6. Completing remaining questions (total: {total_questions})...")
                        
                        while not session.is_completed and session.current_question < total_questions:
                            # Get next question
                            response = client.get(f'/quiz/question/{session_id}/')
                            if response.status_code == 200:
                                context = response.context
                                question = context.get('question')
                                answers = context.get('answers')
                                
                                if answers:
                                    # Submit any answer (first one)
                                    first_answer = answers[0]
                                    submit_data = {'answer_id': first_answer.id}
                                    client.post(
                                        f'/quiz/submit_answer/{session_id}/',
                                        json.dumps(submit_data),
                                        content_type='application/json'
                                    )
                                    
                                    # Refresh session
                                    session.refresh_from_db()
                                    print(f"   Question {session.current_question}/{total_questions} completed")
                            else:
                                break
                        
                        print("\n7. Testing Quiz Result...")
                        response = client.get(f'/quiz/result/{session_id}/')
                        print(f"   Result page status: {response.status_code}")
                        
                        if response.status_code == 200:
                            context = response.context
                            result = context.get('result')
                            if result:
                                print(f"   Final score: {result.final_score}")
                                print(f"   Percentage: {result.percentage}%")
                                print(f"   Character: {result.character_result}")
                                print("   ✓ Quiz result generated successfully")
                            
                            print("\n8. Testing Leaderboard...")
                            response = client.get('/quiz/leaderboard/')
                            print(f"   Leaderboard status: {response.status_code}")
                            
                            if response.status_code == 200:
                                results = response.context.get('results', [])
                                print(f"   Leaderboard entries: {len(results)}")
                                print("   ✓ Leaderboard working")
                                
                                print("\n=== QUIZ FLOW TEST COMPLETED SUCCESSFULLY ===")
                                return True
    
    print("\n❌ Quiz flow test failed - insufficient test data")
    return False

if __name__ == '__main__':
    try:
        success = test_quiz_flow()
        if success:
            print("\n🎉 All tests passed!")
        else:
            print("\n❌ Some tests failed!")
    except Exception as e:
        print(f"\n💥 Test error: {str(e)}")
        import traceback
        traceback.print_exc()
