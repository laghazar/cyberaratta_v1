#!/usr/bin/env python
"""
Simple Quiz Data Check Script
"""

import os
import sys
import django

# Setup Django environment
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberaratta.settings')
django.setup()

from apps.quiz.models import QuizCategory, Question, Answer

def check_quiz_data():
    """Check if we have sufficient quiz data for testing"""
    print("=== QUIZ DATA CHECK ===")
    
    categories = QuizCategory.objects.filter(is_active=True)
    print(f"Active categories: {categories.count()}")
    
    testable_categories = []
    
    for cat in categories:
        print(f"\nCategory: {cat.name} ({cat.category_type})")
        
        for qtype in ['classic', 'millionaire']:
            questions = Question.objects.filter(
                category=cat, 
                question_type=qtype, 
                is_active=True
            ).prefetch_related('answers')
            
            count = questions.count()
            print(f"  {qtype}: {count} questions")
            
            if count > 0:
                # Check if questions have answers
                for i, q in enumerate(questions[:3], 1):  # Check first 3
                    answers = q.answers.all()
                    correct_answers = answers.filter(is_correct=True)
                    print(f"    Q{i}: {len(answers)} answers, {len(correct_answers)} correct")
                    if len(answers) >= 2 and len(correct_answers) >= 1:
                        if cat.name not in [tc[0] for tc in testable_categories]:
                            testable_categories.append((cat.name, cat.id, qtype))
    
    print(f"\n=== TESTABLE COMBINATIONS ===")
    if testable_categories:
        for cat_name, cat_id, qtype in testable_categories:
            print(f"✓ {cat_name} - {qtype}")
        print(f"\nReady for testing: {len(testable_categories)} combinations")
        return True
    else:
        print("❌ No testable combinations found")
        print("\nTo make quiz testable, we need:")
        print("- At least 1 category with questions")
        print("- Questions with at least 2 answers each")
        print("- At least 1 correct answer per question")
        return False

def add_minimal_test_data():
    """Add minimal test data to make quiz functional"""
    print("\n=== ADDING MINIMAL TEST DATA ===")
    
    # Get or create a test category
    test_cat, created = QuizCategory.objects.get_or_create(
        name="Թեստային",
        defaults={
            'category_type': 'school',
            'description': 'Թեստային հարցեր վիկտորինայի ստուգման համար',
            'is_active': True
        }
    )
    
    if created:
        print(f"Created test category: {test_cat.name}")
    
    # Add test questions
    test_questions = [
        {
            'text': 'Ինչ է կիբեռանվտանգությունը?',
            'type': 'classic',
            'answers': [
                ('Համակարգչի պաշտպանություն', True),
                ('Ինտերնետի արագություն', False),
                ('Նոր տեխնոլոգիա', False),
                ('Խաղային ծրագիր', False)
            ]
        },
        {
            'text': 'Ինչ է փիշինգը?',
            'type': 'classic', 
            'answers': [
                ('Ձկնորսություն', False),
                ('Կեղծ նամակներով տվյալների գողություն', True),
                ('Նոր ծրագիր', False),
                ('Վիրուս', False)
            ]
        },
        {
            'text': 'Ինչպիսի գաղտնաբառ է անվտանգ?',
            'type': 'millionaire',
            'answers': [
                ('123456', False),
                ('password', False), 
                ('Բարդ գաղտնաբառ տառերով, թվերով և նշաններով', True),
                ('qwerty', False)
            ]
        }
    ]
    
    questions_added = 0
    for q_data in test_questions:
        # Check if question exists
        existing = Question.objects.filter(
            question_text=q_data['text'],
            category=test_cat,
            question_type=q_data['type']
        ).first()
        
        if not existing:
            # Create question
            question = Question.objects.create(
                question_text=q_data['text'],
                question_type=q_data['type'],
                category=test_cat,
                difficulty=1,
                points=10,
                explanation='Թեստային բացատրություն',
                is_active=True
            )
            
            # Add answers
            for answer_text, is_correct in q_data['answers']:
                Answer.objects.create(
                    question=question,
                    answer_text=answer_text,
                    is_correct=is_correct
                )
            
            questions_added += 1
            print(f"Added question: {q_data['text'][:50]}...")
    
    print(f"Added {questions_added} new questions")
    return questions_added > 0

if __name__ == '__main__':
    if not check_quiz_data():
        print("\nAdding test data...")
        add_minimal_test_data()
        print("\nRe-checking data...")
        check_quiz_data()
