import json
import random
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from django.utils import timezone
from .models import QuizCategory, Question, Answer, QuizSession, QuizResult
from apps.core.utils import update_statistics

def quiz_home(request):
    """Քուիզի գլխավոր էջ"""
    categories = QuizCategory.objects.filter(is_active=True)
    return render(request, 'quiz/home.html', {'categories': categories})

def start_quiz(request):
    """Քուիզի սկսում"""
    if request.method == 'POST':
        category_id = request.POST.get('category')
        question_type = request.POST.get('question_type')
        
        category = get_object_or_404(QuizCategory, id=category_id)
        session_key = request.session.session_key or request.session.create()
        
        quiz_session = QuizSession.objects.create(
            session_key=session_key,
            category=category,
            question_type=question_type,
            total_questions=10 if question_type != 'millionaire' else 15
        )
        
        return redirect('quiz:quiz_question', session_id=quiz_session.id)
    
    categories = QuizCategory.objects.filter(is_active=True)
    return render(request, 'quiz/start.html', {'categories': categories})

def quiz_question(request, session_id):
    """Քուիզի հարցեր"""
    session = get_object_or_404(QuizSession, id=session_id)
    
    if session.is_completed:
        return redirect('quiz:quiz_result', session_id=session_id)
    
    questions = Question.objects.filter(category=session.category, question_type=session.question_type, is_active=True).order_by('?')[:session.total_questions]
    
    if session.current_question >= len(questions):
        return complete_quiz(request, session)
    
    current_question = questions[session.current_question]
    answers = current_question.answers.all()
    
    context = {
        'session': session,
        'question': current_question,
        'answers': answers,
        'question_number': session.current_question + 1,
        'total_questions': session.total_questions,
        'progress': ((session.current_question + 1) / session.total_questions) * 100
    }
    
    template = 'quiz/millionaire.html' if session.question_type == 'millionaire' else 'quiz/question.html'
    return render(request, template, context)

@csrf_exempt
def submit_answer(request, session_id):
    """Պատասխանի ուղարկում"""
    if request.method == 'POST':
        session = get_object_or_404(QuizSession, id=session_id)
        data = json.loads(request.body)
        answer_id = data.get('answer_id')
        
        answer = get_object_or_404(Answer, id=answer_id)
        
        response_data = {
            'correct': answer.is_correct,
            'explanation': answer.question.explanation,
            'points_earned': answer.question.points if answer.is_correct else 0
        }
        
        if answer.is_correct:
            session.score += answer.question.points
        
        session.current_question += 1
        session.save()
        
        return JsonResponse(response_data)

def complete_quiz(request, session):
    """Քուիզի ավարտում"""
    session.is_completed = True
    session.completed_at = timezone.now()
    session.save()
    
    max_score = session.total_questions * 10
    percentage = (session.score / max_score) * 100
    character_result = 'ara' if percentage >= 70 else 'shamiram'
    
    feedback_message = (
        "Շնորհավորում ենք! Դուք նման եք Արա Գեղեցիկին՝ լավ գիտելիքներ ունեք կիբեռանվտանգության մասին:"
        if character_result == 'ara'
        else "Դուք պետք է ավելի զգույշ լինեք։ Խորհուրդ ենք տալիս սովորել կիբեռանվտանգության մասին:"
    )
    
    quiz_result = QuizResult.objects.create(
        session=session,
        final_score=session.score,
        percentage=percentage,
        character_result=character_result,
        feedback_message=feedback_message
    )
    
    return redirect('quiz:quiz_result', session_id=session.id)

def quiz_result(request, session_id):
    """Քուիզի արդյունք"""
    session = get_object_or_404(QuizSession, id=session_id, is_completed=True)
    result = get_object_or_404(QuizResult, session=session)
    
    update_statistics()
    
    context = {
        'session': session,
        'result': result,
    }
    
    return render(request, 'quiz/result.html', context)